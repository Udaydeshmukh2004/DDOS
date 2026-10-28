/**
 * IntelliShield SOC — Phase 8 Enhanced Explainable AI (XAI) Client API.
 * Provides endpoints for Multi-Model Attribution (DT, IF, AE) and Actionable Counterfactuals.
 */

import { getJSON, postJSON, DataState } from "./client.js";

function optsOf(signal) {
  return signal ? { signal } : {};
}

/**
 * Fetch feature names, schema metadata, descriptions, and nominal baseline ranges.
 * @param {AbortSignal} [signal]
 */
export async function fetchXaiFeatures(signal) {
  return getJSON("/api/xai/features", optsOf(signal));
}

/**
 * Fetch XAI attribution and actionable guidance linked to a specific event ID.
 * @param {string} eventId
 * @param {AbortSignal} [signal]
 */
export async function fetchXaiByEvent(eventId, signal) {
  if (!eventId || !String(eventId).trim()) {
    return { state: DataState.EMPTY, data: null, error: null };
  }
  const eid = encodeURIComponent(String(eventId).trim());
  return getJSON(`/api/xai/event/${eid}`, optsOf(signal)).then((r) => {
    if (r.status === 404) {
      return { ...r, state: DataState.EMPTY, data: null, error: null };
    }
    return r;
  });
}

/**
 * Submit a 15-dimensional traffic feature vector for multi-model XAI analysis.
 * @param {number[]} vector 15-element array
 * @param {object|null} [prediction]
 * @param {string|null} [eventId]
 * @param {string|null} [modelId]
 * @param {AbortSignal} [signal]
 */
export async function explainFlow(vector, prediction = null, eventId = null, modelId = null, signal = undefined) {
  return postJSON(
    "/api/xai/explain",
    {
      vector,
      prediction,
      event_id: eventId,
      model_id: modelId,
    },
    optsOf(signal)
  );
}

/**
 * Compute minimal actionable feature perturbations to transition an anomalous flow to NORMAL.
 * @param {number[]} vector 15-element array
 * @param {string} [targetDecision="NORMAL"]
 * @param {number} [maxFeatures=5]
 * @param {AbortSignal} [signal]
 */
export async function fetchCounterfactual(vector, targetDecision = "NORMAL", maxFeatures = 5, signal = undefined) {
  return postJSON(
    "/api/xai/counterfactual",
    {
      vector,
      target_decision: targetDecision,
      max_features: maxFeatures,
    },
    optsOf(signal)
  );
}

