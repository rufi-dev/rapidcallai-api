const { getBillingConfig } = require("./config");

function httpError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}

function assertCanStartWebCall(workspace, cfg = getBillingConfig()) {
  if (!workspace) throw httpError(401, "Unauthorized");
  if (workspace.isPaid) return;
  if (workspace.isTrial) {
    const credit = Number(workspace.trialCreditUsd || 0);
    if (!Number.isFinite(credit) || credit <= 0) {
      throw httpError(402, "Trial ended — add payment method to continue");
    }
    return;
  }
}

function assertCanBuyNumber(workspace, cfg = getBillingConfig()) {
  if (!workspace) throw httpError(401, "Unauthorized");
  if (workspace.isPaid && workspace.hasPaymentMethod) return;
  if (workspace.isTrial && cfg.trialAllowNumberPurchase) return;
  throw httpError(402, "Add payment method to buy a phone number");
}

function assertCanUsePstn(workspace, cfg = getBillingConfig()) {
  if (!workspace) throw httpError(401, "Unauthorized");
  if (workspace.isTrial && cfg.trialAllowPstn) return;
  if (workspace.isPaid && workspace.hasPaymentMethod && workspace.telephonyEnabled) return;
  throw httpError(402, "Add payment method to use phone calls");
}

module.exports = {
  httpError,
  assertCanStartWebCall,
  assertCanBuyNumber,
  assertCanUsePstn,
};


