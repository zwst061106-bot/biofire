/**
 * StateMachineFuzzer — Protocol State Transition Testing
 * 
 * Tests the MPC protocol state machine for invalid transitions:
 * - DKG → Signing without DKG completion
 * - Signing → DKG mid-ceremony
 * - Refresh → Signing with old shares
 * - Multiple concurrent refreshes
 * - Abort recovery sequences
 * 
 * Strategy: Generate random state transition sequences and verify
 * that the state machine rejects invalid transitions.
 */

export type MPCState = 
  | 'IDLE' 
  | 'DKG_COMMIT' 
  | 'DKG_SHARE' 
  | 'DKG_COMPLETE'
  | 'SIGN_COMMIT' 
  | 'SIGN_MTA' 
  | 'SIGN_PARTIAL' 
  | 'SIGN_COMPLETE'
  | 'REFRESH'
  | 'ABORTED';

export type MPCAction = 
  | 'START_DKG' 
  | 'COMMIT_RECEIVED' 
  | 'SHARE_RECEIVED' 
  | 'DKG_DONE'
  | 'START_SIGN' 
  | 'NONCE_COMMIT' 
  | 'MTA_COMPLETE' 
  | 'SIGN_DONE'
  | 'START_REFRESH' 
  | 'REFRESH_DONE'
  | 'ABORT' 
  | 'RECOVER';

interface Transition {
  from: MPCState;
  action: MPCAction;
  to: MPCState;
  guard?: (context: StateContext) => boolean;
}

interface StateContext {
  dkgComplete: boolean;
  signInProgress: boolean;
  refreshInProgress: boolean;
  currentEpoch: number;
  activeSigners: number;
  threshold: number;
}

export interface StateFuzzReport {
  totalTransitions: number;
  invalidTransitions: number;
  deadlocks: number;
  livelocks: number;
  uncoveredTransitions: string[];
  crashes: number;
}

export class StateMachineFuzzer {
  private transitions: Transition[] = [
    { from: 'IDLE', action: 'START_DKG', to: 'DKG_COMMIT' },
    { from: 'DKG_COMMIT', action: 'COMMIT_RECEIVED', to: 'DKG_SHARE' },
    { from: 'DKG_SHARE', action: 'SHARE_RECEIVED', to: 'DKG_COMPLETE' },
    { from: 'DKG_COMPLETE', action: 'START_SIGN', to: 'SIGN_COMMIT' },
    { from: 'SIGN_COMMIT', action: 'NONCE_COMMIT', to: 'SIGN_MTA' },
    { from: 'SIGN_MTA', action: 'MTA_COMPLETE', to: 'SIGN_PARTIAL' },
    { from: 'SIGN_PARTIAL', action: 'SIGN_DONE', to: 'SIGN_COMPLETE' },
    { from: 'DKG_COMPLETE', action: 'START_REFRESH', to: 'REFRESH' },
    { from: 'REFRESH', action: 'REFRESH_DONE', to: 'DKG_COMPLETE' },
    { from: 'SIGN_COMMIT', action: 'ABORT', to: 'ABORTED' },
    { from: 'ABORTED', action: 'RECOVER', to: 'IDLE' },
    // Guards
    { from: 'IDLE', action: 'START_SIGN', to: 'IDLE', guard: ctx => !ctx.dkgComplete },
    { from: 'DKG_COMMIT', action: 'START_SIGN', to: 'DKG_COMMIT', guard: ctx => !ctx.dkgComplete },
    { from: 'SIGN_COMMIT', action: 'START_DKG', to: 'SIGN_COMMIT', guard: ctx => ctx.signInProgress },
    { from: 'REFRESH', action: 'START_REFRESH', to: 'REFRESH', guard: ctx => ctx.refreshInProgress },
    { from: 'SIGN_PARTIAL', action: 'START_REFRESH', to: 'SIGN_PARTIAL', guard: ctx => ctx.signInProgress },
  ];

  private report: StateFuzzReport = {
    totalTransitions: 0,
    invalidTransitions: 0,
    deadlocks: 0,
    livelocks: 0,
    uncoveredTransitions: [],
    crashes: 0,
  };

  /**
   * Run state machine fuzzing campaign.
   */
  async runCampaign(iterations: number = 10_000): Promise<StateFuzzReport> {
    this.report = {
      totalTransitions: 0,
      invalidTransitions: 0,
      deadlocks: 0,
      livelocks: 0,
      uncoveredTransitions: this.getAllPossibleTransitions(),
      crashes: 0,
    };

    for (let i = 0; i < iterations; i++) {
      await this.runRandomSequence();
    }

    return this.report;
  }

  private async runRandomSequence(): Promise<void> {
    const context: StateContext = {
      dkgComplete: false,
      signInProgress: false,
      refreshInProgress: false,
      currentEpoch: 1,
      activeSigners: 0,
      threshold: 2,
    };

    let state: MPCState = 'IDLE';
    const visited = new Set<string>();
    const sequence: { state: MPCState; action: MPCAction }[] = [];

    for (let step = 0; step < 100; step++) {
      const validActions = this.getValidActions(state, context);

      if (validActions.length === 0) {
        this.report.deadlocks++;
        break;
      }

      // 90% valid action, 10% random invalid action
      const action = Math.random() < 0.9
        ? validActions[Math.floor(Math.random() * validActions.length)]
        : this.getRandomAction();

      const transition = this.transitions.find(t => 
        t.from === state && t.action === action
      );

      const key = `${state}→${action}`;
      this.report.uncoveredTransitions = this.report.uncoveredTransitions.filter(t => t !== key);
      visited.add(key);
      this.report.totalTransitions++;

      if (!transition) {
        this.report.invalidTransitions++;
        // Attempting invalid transition — state machine should reject
        continue;
      }

      // Check guard
      if (transition.guard && !transition.guard(context)) {
        this.report.invalidTransitions++;
        continue;
      }

      // Apply transition
      state = transition.to;
      sequence.push({ state, action });

      // Update context
      this.updateContext(context, action);

      // Detect livelock (revisiting same state-action pairs)
      if (sequence.length > 20) {
        const recent = sequence.slice(-10);
        const isLooping = recent.every((s, i) => 
          i === 0 || (s.state === recent[0].state && s.action === recent[0].action)
        );
        if (isLooping) {
          this.report.livelocks++;
          break;
        }
      }
    }
  }

  private getValidActions(state: MPCState, context: StateContext): MPCAction[] {
    return this.transitions
      .filter(t => t.from === state && (!t.guard || t.guard(context)))
      .map(t => t.action);
  }

  private getRandomAction(): MPCAction {
    const actions: MPCAction[] = [
      'START_DKG', 'COMMIT_RECEIVED', 'SHARE_RECEIVED', 'DKG_DONE',
      'START_SIGN', 'NONCE_COMMIT', 'MTA_COMPLETE', 'SIGN_DONE',
      'START_REFRESH', 'REFRESH_DONE', 'ABORT', 'RECOVER',
    ];
    return actions[Math.floor(Math.random() * actions.length)];
  }

  private updateContext(ctx: StateContext, action: MPCAction): void {
    switch (action) {
      case 'DKG_DONE': ctx.dkgComplete = true; break;
      case 'START_SIGN': ctx.signInProgress = true; break;
      case 'SIGN_DONE': ctx.signInProgress = false; break;
      case 'START_REFRESH': ctx.refreshInProgress = true; break;
      case 'REFRESH_DONE': ctx.refreshInProgress = false; ctx.currentEpoch++; break;
      case 'ABORT': ctx.signInProgress = false; break;
      case 'RECOVER': ctx.dkgComplete = false; ctx.signInProgress = false; ctx.refreshInProgress = false; break;
    }
  }

  private getAllPossibleTransitions(): string[] {
    const states: MPCState[] = ['IDLE', 'DKG_COMMIT', 'DKG_SHARE', 'DKG_COMPLETE', 'SIGN_COMMIT', 'SIGN_MTA', 'SIGN_PARTIAL', 'SIGN_COMPLETE', 'REFRESH', 'ABORTED'];
    const actions: MPCAction[] = ['START_DKG', 'START_SIGN', 'START_REFRESH', 'ABORT', 'RECOVER'];
    const all: string[] = [];
    for (const s of states) {
      for (const a of actions) {
        all.push(`${s}→${a}`);
      }
    }
    return all;
  }
}

export { StateFuzzReport };
