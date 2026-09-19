# Juice Shop BurpNexus test export

This is a safe synthetic BurpNexus JSON export for testing the VS Code extension with an OWASP Juice Shop source checkout. It contains three localhost examples and redacted fixture values; it does not contact Juice Shop or contain real credentials.

In VS Code, run **BurpNexus: Connect Export to Source Repository**, select this `juice-shop-export` directory first, then select the folder containing your Juice Shop source. Open **BurpNexus: Open AI Analysis**, choose an endpoint, and inspect the candidate/unmapped state.

The source folder must be the repository root that contains Juice Shop's `routes`, `server`, or equivalent application source directories. Mapping depends on the exact Juice Shop revision and may show `unmapped` for routes whose framework or generated wiring is outside the extension's supported static patterns. That is useful test output; it is not an indication that the endpoint is absent.

The three fixture requests are:

- `GET http://localhost:3000/rest/products/search?q=apple`
- `GET http://localhost:3000/api/Products/1`
- `POST http://localhost:3000/rest/user/login`

Use the **Public bug bounty lessons** or **Authentication / sessions / browser trust** review focus after selecting an endpoint. The fixture is for mapping and UI validation; it does not execute a scan.
