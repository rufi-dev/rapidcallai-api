const { getBillingConfig } = require("./config");
const {
  ensureOpenMeterCustomerForWorkspace,
  linkStripeCustomerToOpenMeterCustomer,
  grantOpenMeterEntitlement,
} = require("./openmeter");

function safeNum(x, def = 0) {
  const n = Number(x);
  return Number.isFinite(n) ? n : def;
}

/**
 * Best-effort provisioning:
 * - Ensure Stripe customer exists (metadata workspace_id)
 * - Ensure OpenMeter customer exists (key = workspace.id, subjectKeys=[workspace.id])
 * - Link OpenMeter customer to Stripe customer
 * - Grant $TRIAL_CREDIT_USD worth of credits in OpenMeter (requires an existing entitlement)
 *
 * This function should NEVER throw; callers should treat as background/best-effort.
 */
async function provisionBillingForWorkspace({ store, stripeBilling, workspace, user }) {
  if (!store || !stripeBilling || !workspace?.id) return { ok: false, skipped: true, reason: "missing inputs" };

  const cfg = getBillingConfig();
  const apiUrl = process.env.OPENMETER_API_URL;
  const apiKey = process.env.OPENMETER_API_KEY;

  let stripeCustomerId = workspace.stripeCustomerId ?? null;
  try {
    if (!stripeCustomerId) {
      const res = await stripeBilling.ensureStripeCustomerForWorkspace({
        ...workspace,
        userEmail: user?.email,
      });
      stripeCustomerId = res?.customerId ?? null;
      if (stripeCustomerId) {
        await store.updateWorkspace(workspace.id, { stripeCustomerId });
      }
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn("[billing.provision] stripe customer failed", e?.message || e);
  }

  // OpenMeter: create/update customer and link to Stripe (best effort).
  try {
    const om = await ensureOpenMeterCustomerForWorkspace({
      apiUrl,
      apiKey,
      workspace,
      stripeCustomerId,
      userEmail: user?.email,
    });
    if (om?.ok && om.customer) {
      // Prefer storing the customer key (we use workspace.id as key); it's the most stable identifier across APIs.
      const omCustomerId =
        String(om.customer.key || "").trim() ||
        String(om.customer.id || "").trim() ||
        String(workspace.id || "").trim() ||
        null;
      if (omCustomerId && !workspace.openmeterCustomerId) {
        await store.updateWorkspace(workspace.id, { openmeterCustomerId: omCustomerId });
      }
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn("[billing.provision] openmeter customer failed", e?.message || e);
  }

  try {
    if (stripeCustomerId) {
      await linkStripeCustomerToOpenMeterCustomer({
        apiUrl,
        apiKey,
        customerIdOrKey: workspace.id,
        stripeCustomerId,
      });
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn("[billing.provision] openmeter stripe link failed", e?.message || e);
  }

  // Trial credit grant in OpenMeter (deducts before invoicing, depending on billing profile).
  // Requires you to have an existing entitlement configured in OpenMeter.
  try {
    const wsLatest = await store.getWorkspace(workspace.id);
    if (wsLatest && !wsLatest.openmeterCreditGrantedAt && !wsLatest.openmeterCreditGrantId) {
      const entitlementKey = String(process.env.OPENMETER_CREDIT_ENTITLEMENT_KEY || "").trim();
      if (entitlementKey) {
        const creditUsd = safeNum(process.env.TRIAL_CREDIT_USD, safeNum(cfg.trialCreditUsd, 20));
        const amount = Math.round(Math.max(0, creditUsd) * 100); // cents
        if (amount > 0) {
          const grantRes = await grantOpenMeterEntitlement({
            apiUrl,
            apiKey,
            customerIdOrKey: wsLatest.id,
            entitlementIdOrFeatureKey: entitlementKey,
            amount,
            metadata: {
              externalId: `trial_credit:${wsLatest.id}`,
              currency: "USD",
              amountCents: amount,
            },
          });
          if (grantRes?.ok && grantRes.grant?.id) {
            await store.updateWorkspace(wsLatest.id, {
              openmeterCreditGrantId: String(grantRes.grant.id),
              openmeterCreditGrantedAt: Date.now(),
            });
          }
        }
      }
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn("[billing.provision] openmeter credit grant failed", e?.message || e);
  }

  return { ok: true };
}

module.exports = { provisionBillingForWorkspace };


