# Administration UI visual standards

This document defines layout and interaction invariants for the Camellia Nexus administration UI.
The console keeps its own Inter typography, compact density, radii, surfaces, Lucide icons, and
responsive layout. It is not intended to reproduce the sibling desktop application's visual style.

## Controls

- Form, standalone, compact-member, and filter controls use the administration UI's control tokens.
  Page-local vertical padding must not be used to repair the geometry of a shared control.
- Controls of the same kind and density have the same block size and optical center. A select's
  interactive surface fills its visible border box.
- Short enumerated values such as role, state, plan, severity, and decision are centered. Long entity
  values such as account identifiers, offers, or compound identities are start-aligned.
- Application-rendered single-select menus use one text column and do not show a checkmark or reserve
  mirror columns. Selected options use the console's accent surface, text treatment, font weight, and
  native selected state.
- Native mobile or unsupported-browser pickers may use platform chrome. Genuine booleans and
  multi-select collections remain checkboxes.

## Form and action layout

- Labels, controls, help text, validation text, and reasons use the shared form gaps and remain
  associated by accessible name and description.
- Placeholders and examples use regular weight and lower emphasis than entered values. They never
  replace required instructions or the control's accessible label.
- Keep filters, primary commands, destructive commands, and read-only metadata in separate semantic
  groups. Similar height does not imply that controls should have equal width or identical chrome.
- Text-bearing buttons use the console's inline-flex alignment and icon gap. Lucide icons remain the
  administration icon language; do not replace them with desktop artwork.
- Long account IDs, names, email addresses, errors, and audit reasons wrap or ellipsize inside their
  owning region and must not widen dialogs or the document.

## Team and conditional states

- Invitation account selection is start-aligned; invitation role and editable member role/status are
  centered. Read-only members use read-only fields and status components, not disabled pseudo-inputs.
- Verify empty workspaces, read-only and write-enabled administrators, pagination, pending invitation
  delivery, saving, stale-version reload, errors, and long member identities.
- Permission-based visibility is presentation only. Every mutation remains authorized by the server.

## Responsive and accessibility review

1. Test light and dark modes, Chinese and English, every supported text-size setting, and the 600/601
   responsive boundary.
2. Confirm that dialogs retain reachable headers, errors, scrollable bodies, and footers.
3. Verify keyboard traversal, focus trapping and restoration, visible focus, reduced motion, and
   screen-reader names.
4. Assert no document or toolbar overflow and keep representative Playwright screenshots for
   populated, empty, error, and compact states.
