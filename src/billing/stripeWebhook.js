const express = require("express");
const { provisionBillingForWorkspace } = require("./provision");

function registerStripeWebhookRoute(app, { store, stripeBilling }) {
  // Must be registered before express.json() middleware.
  app.post("/api/stripe/webhook", express.raw({ type: "application/json" }), async (req, res) => {
    const stripe = stripeBilling.getStripe();
    const secret = String(process.env.STRIPE_WEBHOOK_SECRET || "").trim();
    if (!stripe || !secret) return res.status(404).send("Not configured");

    const sig = String(req.headers["stripe-signature"] || "");
    let event = null;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, secret);
    } catch (e) {
      return res.status(400).send(`Webhook Error: ${e instanceof Error ? e.message : "invalid signature"}`);
    }

    try {
      if (event.type === "checkout.session.completed") {
        const session = event.data.object;
        // Only handle OUR upgrade flow (Checkout in setup mode).
        if (String(session?.mode || "") !== "setup") return res.json({ received: true });
        const workspaceId = String(session?.metadata?.workspace_id || "").trim();
        const customerId = String(session?.customer || "").trim();
        const setupIntentId = String(session?.setup_intent || "").trim();

        if (workspaceId && customerId && store) {
          const ws = await store.getWorkspace(workspaceId);
          if (ws) {
            // Verify SetupIntent succeeded and has a payment method, then set it as default for invoices.
            if (setupIntentId) {
              const si = await stripe.setupIntents.retrieve(setupIntentId);
              if (si.status !== "succeeded") {
                return res.status(400).send("SetupIntent not succeeded");
              }
              const pm = typeof si.payment_method === "string" ? si.payment_method : si.payment_method?.id;
              if (pm) {
                await stripe.customers.update(customerId, {
                  invoice_settings: { default_payment_method: pm },
                });
              } else {
                return res.status(400).send("No payment method on SetupIntent");
              }
            }

            // Mark paid + payment method on file. Trial billing stops here.
            await store.updateWorkspace(workspaceId, {
              stripeCustomerId: customerId,
              hasPaymentMethod: true,
              isPaid: true,
              isTrial: false,
              telephonyEnabled: true,
            });

            const ws2 = await store.getWorkspace(workspaceId);
            if (ws2 && !ws2.stripeSubscriptionId) {
              const phoneNumbers = await store.listPhoneNumbers(workspaceId);
              const sub = await stripeBilling.createSubscriptionForWorkspace({
                workspaceId,
                customerId,
                phoneNumbersCount: phoneNumbers.length,
              });
              await store.updateWorkspace(workspaceId, {
                stripeSubscriptionId: sub.subscriptionId,
                stripePhoneNumbersItemId: sub.phoneNumbersItemId,
              });
            }

            // Best-effort: ensure OpenMeter customer exists + is linked to this Stripe customer.
            try {
              const ws3 = await store.getWorkspace(workspaceId);
              if (ws3) await provisionBillingForWorkspace({ store, stripeBilling, workspace: ws3, user: null });
            } catch (e) {
              console.warn("[stripe.webhook] openmeter provision failed", e?.message || e);
            }
          }
        }
      }

      return res.json({ received: true });
    } catch (e) {
      console.warn("[stripe.webhook] handler failed", e?.message || e);
      return res.status(500).send("Webhook handler failed");
    }
  });
}

module.exports = { registerStripeWebhookRoute };


