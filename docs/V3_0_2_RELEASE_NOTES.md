# Reconner v3.0.2

This patch restores reliable scan controls across desktop and mobile viewports.

## Scan dialog reliability

- Dialogs now render through a document-level portal, so animated or
  transformed workspace containers cannot clip or reposition them beneath the
  navigation shell.
- Every dialog is constrained to the visible viewport and locks background
  scrolling while open.
- Long dialogs use one predictable content scroller with fixed headers and an
  optional fixed action footer.
- The scan phase picker no longer traps scrolling in a nested region. Cancel
  and Start Scan remain visible and clickable while reviewing every phase.
- Browser regression coverage verifies the scan title, profile controls and
  action footer remain inside the viewport before and after scrolling.
