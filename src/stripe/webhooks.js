"use strict";

const Stripe = require("stripe");
const store = require("../store_pg");
const metronome = require("../metronome/client");
const { planFromStripePriceId, getRateCardIdForPlan } = require("../billing/config");

const stripeSecret = process.env.STRIPE_SECRET_KEY;
const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

function getStripe() {
  if (!stripeSecret || !stripeSecret.trim()) return null;
  return new Stripe(stripeSecret.trim(), { apiVersion: "2024-11-20.acacia" });
}

/**
 * Ensure Metronome customer exists for workspace; create if not.
 * @returns {Promise<{ metronomeCustomerId: string }>}
 */
async function ensureMetronomeCustomer(workspace) {
  if (workspace.metronomeCustomerId) {
    return { metronomeCustomerId: workspace.metronomeCustomerId };
  }
  const name = workspace.name || `Workspace ${workspace.id}`;
  const ingestAliases = [workspace.id];
  if (workspace.userId) ingestAliases.push(workspace.userId);
  const { id } = await metronome.createCustomer({
    name,
    ingestAliases,
    stripeCustomerId: workspace.stripeCustomerId || undefined,
  });
  await store.updateWorkspace(workspace.id, { metronomeCustomerId: id });
  return { metronomeCustomerId: id };
}

/**
 * Resolve rate card ID for plan (env or list by name).
 */
async function resolveRateCardId(plan) {
  let id = getRateCardIdForPlan(plan);
  if (id) return id;
  const cards = await metronome.listRateCards();
  const nameMap = {
    starter: "RapidCall Starter",
    pro: "RapidCall Pro",
    scale: "RapidCall Scale",
  };
  const want = nameMap[plan];
  const found = cards.find((c) => c.name && c.name.toLowerCase().includes(want.toLowerCase()));
  return found ? found.id : null;
}

/**
 * Provision or update Metronome contract for workspace to the given plan.
 * On plan change: end current contract at now, create new contract.
 */
async function provisionMetronomeContract(workspace, plan) {
  const rateCardId = await resolveRateCardId(plan);
  if (!rateCardId) {
    throw new Error(`Metronome rate card not found for plan: ${plan}. Set METRONOME_RATE_CARD_*_ID or ensure rate cards exist.`);
  }
  const { metronomeCustomerId } = await ensureMetronomeCustomer(workspace);
  const nowIso = new Date().toISOString();

  if (workspace.metronomeContractId) {
    try {
      await metronome.updateContractEndDate({
        customerId: metronomeCustomerId,
        contractId: workspace.metronomeContractId,
        endingBefore: nowIso,
      });
    } catch (e) {
      // contract may already be ended
    }
  }

  const { id: contractId } = await metronome.createContract({
    customerId: metronomeCustomerId,
    rateCardId,
    startingAt: nowIso,
    name: `RapidCall ${plan.charAt(0).toUpperCase() + plan.slice(1)}`,
    stripeCustomerId: workspace.stripeCustomerId || undefined,
  });

  await store.updateWorkspace(workspace.id, {
    metronomeContractId: contractId,
    billingPlan: plan,
    isPaid: true,
    hasPaymentMethod: true,
  });
  return { contractId };
}

/**
 * End Metronome contract at given timestamp (e.g. subscription period end).
 */
async function endMetronomeContract(workspace, endingBeforeIso) {
  if (!workspace.metronomeContractId || !workspace.metronomeCustomerId) return;
  try {
    await metronome.updateContractEndDate({
      customerId: workspace.metronomeCustomerId,
      contractId: workspace.metronomeContractId,
      endingBefore: endingBeforeIso,
    });
  } catch (e) {
    // ignore
  }
  await store.updateWorkspace(workspace.id, {
    metronomeContractId: null,
    billingPlan: null,
    isPaid: false,
    stripeSubscriptionId: null,
  });
}

/**
 * Handle checkout.session.completed: link workspace to Stripe customer and subscription.
 */
async function handleCheckoutSessionCompleted(session) {
  const workspaceId = session.client_reference_id || session.metadata?.workspace_id;
  if (!workspaceId) return;
  const workspace = await store.getWorkspace(workspaceId);
  if (!workspace) return;
  const updates = {};
  if (session.customer && !workspace.stripeCustomerId) updates.stripeCustomerId = session.customer;
  if (session.subscription && !workspace.stripeSubscriptionId) updates.stripeSubscriptionId = session.subscription;
  if (Object.keys(updates).length > 0) {
    await store.updateWorkspace(workspaceId, updates);
  }
}

/**
 * Handle customer.subscription.created or updated: provision Metronome.
 */
async function handleSubscriptionUpdated(subscription) {
  const stripeCustomerId = typeof subscription.customer === "string" ? subscription.customer : subscription.customer?.id;
  if (!stripeCustomerId) return;
  const workspace = await store.getWorkspaceByStripeCustomerId(stripeCustomerId);
  if (!workspace) return;

  await store.updateWorkspace(workspace.id, { stripeSubscriptionId: subscription.id });

  const item = subscription.items?.data?.[0];
  const priceId = item?.price?.id;
  const plan = planFromStripePriceId(priceId);
  if (!plan) return;

  if (metronome.getToken()) {
    await provisionMetronomeContract(workspace, plan);
  }
}

/**
 * Handle customer.subscription.deleted: end Metronome contract at period end.
 */
async function handleSubscriptionDeleted(subscription) {
  const stripeCustomerId = typeof subscription.customer === "string" ? subscription.customer : subscription.customer?.id;
  if (!stripeCustomerId) return;
  const workspace = await store.getWorkspaceByStripeCustomerId(stripeCustomerId);
  if (!workspace) return;

  const periodEnd = subscription.current_period_end;
  const endingBefore = periodEnd ? new Date(periodEnd * 1000).toISOString() : new Date().toISOString();

  if (metronome.getToken() && workspace.metronomeContractId) {
    await endMetronomeContract(workspace, endingBefore);
  } else {
    await store.updateWorkspace(workspace.id, {
      metronomeContractId: null,
      billingPlan: null,
      isPaid: false,
      stripeSubscriptionId: null,
    });
  }
}

/**
 * Parse raw body and verify Stripe signature; return event or throw.
 */
function verifyWebhook(rawBody, signature) {
  if (!webhookSecret || !rawBody) throw new Error("Missing webhook secret or body");
  const stripe = getStripe();
  if (!stripe) throw new Error("Stripe not configured");
  return stripe.webhooks.constructEvent(rawBody, signature, webhookSecret);
}

/**
 * Route handler: expects raw body and stripe-signature header.
 */
async function handleWebhook(rawBody, signature) {
  const event = verifyWebhook(rawBody, signature);
  const stripe = getStripe();
  let subscription;

  switch (event.type) {
    case "checkout.session.completed": {
      const session = event.data.object;
      await handleCheckoutSessionCompleted(session);
      break;
    }
    case "customer.subscription.created":
    case "customer.subscription.updated":
      subscription = event.data.object;
      await handleSubscriptionUpdated(subscription);
      break;
    case "customer.subscription.deleted":
      subscription = event.data.object;
      await handleSubscriptionDeleted(subscription);
      break;
    default:
      break;
  }
  return { received: true };
}

module.exports = {
  getStripe,
  handleWebhook,
  verifyWebhook,
  ensureMetronomeCustomer,
  provisionMetronomeContract,
  endMetronomeContract,
};
