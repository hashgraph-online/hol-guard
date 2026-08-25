export type SupplyChainRepairStepFailure = {
  step: "package_shims" | "runtime_activation" | "intelligence_sync";
  message: string;
};

export type SupplyChainRepairRemainingStep = {
  step: "intelligence_sync";
  message: string;
  action: "connect";
};

export type SupplyChainRepairResult = {
  repaired: boolean;
  completed_steps: string[];
  failed_steps: SupplyChainRepairStepFailure[];
  remaining_steps: SupplyChainRepairRemainingStep[];
  message: string;
};
