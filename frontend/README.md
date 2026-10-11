# Mock accounts and source visibility

Use the **Mock account** selector to switch between Alex Morgan, Sam Rivera, and Jordan Lee.
On first use in this browser, existing backend sources are assigned to Alex. New file selections,
folders, and repositories belong to the account that submits them. The sample workspace is shared.

In **Input sources → Added sources**, **Remove** hides one source and **Remove all** hides the
current account's added sources. Each file/folder selection is a single source. The analysis page's
**Remove from view** button does the same thing. Removal never calls a deletion endpoint, deletes
database records, or cancels a server analysis. Hidden sources stay hidden after refresh.

Ownership and hidden-source settings live in browser storage under `quantumtrace-mock:*`.
These are demo accounts, with browser-local filtering rather than backend authentication or
authorization. Clearing browser storage resets the assignments; a different browser has its own
assignments. If storage is unavailable, the demo works for the current page only. Existing backend
API requests and database schemas are unchanged.

Run the frontend checks from the repository root:

```sh
node --test frontend/*.test.mjs
```

The checks exercise account isolation, individual/bulk removal without deletion requests,
reload persistence, and account switches or removal during an in-flight submission.
