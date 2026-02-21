"use strict";

const PLANS = ["starter", "pro", "scale"];

function getStripePriceIds() {
  return {
    starter: process.env.STRIPE_PRICE_STARTER || null,
    pro: process.env.STRIPE_PRICE_PRO || null,
    scale: process.env.STRIPE_PRICE_SCALE || null,
  };
}

function getMetronomeRateCardIds() {
  return {
    starter: process.env.METRONOME_RATE_CARD_STARTER_ID || null,
    pro: process.env.METRONOME_RATE_CARD_PRO_ID || null,
    scale: process.env.METRONOME_RATE_CARD_SCALE_ID || null,
  };
}

/**
 * Resolve plan from Stripe price ID.
 * @param {string} priceId - Stripe price id (e.g. price_xxx)
 * @returns {'starter'|'pro'|'scale'|null}
 */
function planFromStripePriceId(priceId) {
  if (!priceId) return null;
  const ids = getStripePriceIds();
  if (ids.starter === priceId) return "starter";
  if (ids.pro === priceId) return "pro";
  if (ids.scale === priceId) return "scale";
  return null;
}

/**
 * Get Metronome rate card ID for a plan. Use env first; otherwise null (caller may resolve via listRateCards).
 * @param {'starter'|'pro'|'scale'} plan
 * @returns {string|null}
 */
function getRateCardIdForPlan(plan) {
  const ids = getMetronomeRateCardIds();
  return ids[plan] || null;
}

module.exports = {
  PLANS,
  getStripePriceIds,
  getMetronomeRateCardIds,
  planFromStripePriceId,
  getRateCardIdForPlan,
};
