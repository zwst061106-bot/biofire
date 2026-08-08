import { Counter, Gauge, Histogram, register } from 'prom-client';

export const signingOpsCounter = new Counter({
  name: 'biofire_signing_operations_total',
  help: 'Total MPC signing operations',
  labelNames: ['chain', 'status'],
});

export const dkgCounter = new Counter({
  name: 'biofire_dkg_ceremonies_total',
  help: 'Total DKG executions',
});

export const policyViolationCounter = new Counter({
  name: 'biofire_policy_violations_total',
  help: 'Transactions blocked by policy',
  labelNames: ['reason'],
});

export const signingDuration = new Histogram({
  name: 'biofire_signing_duration_seconds',
  help: 'Signing ceremony duration',
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5],
});

export const activeNodesGauge = new Gauge({
  name: 'biofire_mpc_active_nodes',
  help: 'Currently active MPC nodes',
});

export class MetricsRegistry {
  incSigningOps(chain: string = 'unknown', status: string = 'success'): void {
    signingOpsCounter.inc({ chain, status });
  }
  incDKG(): void { dkgCounter.inc(); }
  incPolicyViolation(reason: string = 'unknown'): void {
    policyViolationCounter.inc({ reason });
  }
  setActiveNodes(n: number): void { activeNodesGauge.set(n); }
}

export const metricsRegistry = new MetricsRegistry();
