# Local Dashboard Failure Ledger

1. The dashboard opens with marketing language instead of an operational status.
2. The first screen does not tell the developer whether a launch is currently blocked.
3. The first screen does not say which harness was paused in plain language.
4. The first screen does not say which package, skill, or MCP server triggered the stop in plain language.
5. The first screen does not explain whether Guard blocked a first-seen item or a changed item.
6. The dashboard headline is oversized relative to the information density it provides.
7. The headline consumes visual attention without answering an immediate user question.
8. The page treats the approval center like a landing page instead of a working console.
9. The page reads like product positioning instead of incident handling.
10. The UI does not begin with a single sentence that explains the current state.
11. The queue count is visible, but the practical meaning of that count is not.
12. “Queued approvals” is internal jargon that requires extra interpretation.
13. “Current view” adds almost no value to a developer already on the page.
14. “Approval model” is abstract language, not actionable runtime information.
15. The top cards occupy space that should be used for concrete request details.
16. The step cards explain the product instead of the blocked event.
17. The step cards are generic and repeat information already implied by the workflow.
18. The step cards create more reading rather than reducing uncertainty.
19. The layout hides the actual request under a wall of framing copy.
20. The UI forces the user to infer priority instead of highlighting the exact request to resolve next.
21. The queue card leads with the artifact name, not the blocked outcome.
22. The queue card does not show “Guard paused this launch” as the primary message.
23. The queue card does not clearly distinguish “first seen” from “changed since last approval.”
24. The queue card does not show whether this is a package, skill, or MCP server in user terms.
25. The queue card exposes source-scope jargon before decision-relevant context.
26. The queue card uses internal policy action names like `require-reapproval`.
27. The queue card does not translate policy action names into user-facing consequences.
28. The queue card does not tell the user what will happen if they do nothing.
29. The queue card does not tell the user what will happen if they allow the request.
30. The queue card does not tell the user what will happen if they block the request.
31. The detail view is hidden behind an extra click without giving enough value on the queue page.
32. The detail route still uses the artifact name as the hero instead of the blocked launch event.
33. The detail page uses “What Guard saw” instead of “What changed” as the first practical section.
34. The detail page does not present the approval decision as a primary task.
35. The detail page buries the actual action selection too far down the screen.
36. The detail page splits related information into too many equal-weight panels.
37. The detail page does not visually prioritize the reason for the stop.
38. The detail page does not separate “what changed” from “what Guard recommends” strongly enough.
39. The detail page does not clarify whether the current version differs from a trusted baseline or is entirely new.
40. The detail page does not make the safest recommended action unmistakable.
41. The UI uses the word “artifact” heavily without grounding it in a human explanation.
42. The UI uses the word “publisher” without explaining why it matters.
43. The UI uses “scope” before the user understands what each scope changes.
44. The UI exposes raw artifact IDs that are useful for debugging but not for first-pass understanding.
45. The UI exposes config paths before it explains the security consequence.
46. The UI exposes raw receipt terminology without teaching what a receipt means here.
47. The UI exposes “policy” language without translating it into future behavior.
48. The UI uses “stored receipts” in top navigation, which sounds archival, not helpful.
49. The UI exposes “raw queue data” even though most users should not need it first.
50. The UI still mixes operator language and product language in the same view.
51. The UI fails to say “Guard stopped this because X changed.”
52. The UI fails to say “Allowing this means Y.”
53. The UI fails to say “Blocking this means Z.”
54. The UI fails to say “You can choose a narrow or broad trust rule.”
55. The UI fails to say “Most users should start with the narrow option.”
56. The UI fails to say “Broader trust reduces future prompts but increases exposure.”
57. The UI fails to say “Global trust is the broadest and riskiest option.”
58. The UI fails to say “Publisher trust affects future versions.”
59. The UI fails to say “Workspace trust is usually safer than harness-wide trust.”
60. The UI fails to say whether this approval is local-only or synced.
61. The nav and footer borrow portal styling, but the page body does not match the same design system logic.
62. The typography scale is inconsistent with the information hierarchy.
63. The largest text is not the most useful text.
64. The content blocks all have similar contrast and similar weight.
65. The page feels flat because there is no dominant task surface.
66. The page feels decorative instead of purposeful.
67. The page uses too many small all-caps labels.
68. The page uses too much blue-accent labeling without enough semantic differentiation.
69. The page uses too many rounded containers with no clear hierarchy between them.
70. The page spreads attention across too many cards.
71. The page wastes valuable above-the-fold area on abstract explanation.
72. The page has insufficient visual grouping between “status,” “evidence,” and “actions.”
73. The page does not look like a developer approval tool.
74. The page does not look like a trustworthy security decision surface.
75. The page does not look like a queue that should be used repeatedly every day.
76. The approval controls are too generic for the seriousness of the decision.
77. The primary button label “Allow this launch” is better than “Allow,” but still lacks scope context.
78. The block action does not communicate whether it is temporary or persistent.
79. Scope selection via generic cards still demands too much reading before action.
80. The default selected scope is not explained as a recommendation from Guard.
81. The UI does not visually separate recommended scope from all other scopes.
82. The workspace path input appears even when irrelevant.
83. The decision area does not preview the exact rule that will be saved.
84. The decision area does not preview where Guard will remember the choice.
85. The decision area does not show the future consequence of each save.
86. The runtime relationship between harness-native approvals and Guard approvals is not communicated.
87. The dashboard does not tell the user whether this request came from native harness flow, local daemon flow, or terminal fallback.
88. The dashboard does not tell the user whether approving here will resume the active session automatically.
89. The dashboard does not show whether the session is still waiting or already failed.
90. The dashboard does not show whether the harness can be resumed without rerunning the command.
91. The dashboard does not expose the original review command in a helpful advanced section.
92. The dashboard does not expose raw details in a clearly secondary “advanced” area.
93. The developer workflow is not staged from “understand” to “decide” to “resume.”
94. The page lacks a clear empty-state education path for first-time users.
95. The page lacks an obvious “why Guard exists” explanation tied to malicious or changing tooling behavior.
96. The visual review loop was not validated against the actual developer question set.
97. The design iteration depended too long on stale runtime surfaces instead of a proper dev-mode UI.
98. The build was not visually revalidated quickly enough after logo and copy changes.
99. The design did not start from a developer console mental model.
100. The dashboard solved for resemblance to portal chrome before solving for comprehension and task completion.
