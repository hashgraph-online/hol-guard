# Public policy recipes

HOL Guard public policy recipes are inert, reviewable starting points for the existing Guard policy system. A recipe is not applied by downloading or validating it.

The local `guard-policy-recipe/v1` validator accepts only a narrow schema with an exact action, exact matcher, limitations, reviewed date, and safe synthetic fixtures. Unknown fields, unsupported matcher/action values, wildcard matchers, and inconsistent fixtures are rejected.

Recipes do not contain an apply flag, executable command, workspace credential, token, or bypass path. To enforce a recipe, review it in Guard Policy Studio and use the normal policy approval, rollout, signed policy-bundle delivery, and local bundle-verification flow.

Validation confirms only that the downloaded recipe artifact matches this structural and fixture contract. It does not claim the policy covers every equivalent action or every harness/event surface.
