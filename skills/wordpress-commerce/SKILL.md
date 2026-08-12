---
name: wordpress-commerce
description: Diagnose configured WordPress and WooCommerce installations through read-only REST API tools.
---

# WordPress and WooCommerce Diagnostics

The MCP server can inspect one configured WordPress/WooCommerce environment
through environment variables. All tools are read-only; never paste
credentials into tool arguments.

## WordPress

Required:
- `WORDPRESS_BASE_URL` (must be HTTPS).

Optional (needed for plugin/theme/user listing):
- `WORDPRESS_USERNAME`
- `WORDPRESS_APP_PASSWORD` (an Application Password, not the login password).

Workflow:
1. `wordpress_rest_index` to confirm the WP REST API is reachable and to
   discover which namespaces are exposed (wp/v2, wc/v3, custom plugins).
2. `wordpress_plugins` to list installed plugins, status, version and
   pending updates.
3. `wordpress_themes` to list installed themes and active status.
4. `wordpress_users` to enumerate user accounts — treat as sensitive and
   restrict to authorized context.

Always include a clear error message if `WORDPRESS_BASE_URL` is missing —
the toolkit never invents URLs.

## WooCommerce

Required:
- `WOOCOMMERCE_BASE_URL` (HTTPS).
- `WOOCOMMERCE_KEY` and `WOOCOMMERCE_SECRET` (REST API consumer key/secret,
   preferably with read-only permissions).

Workflow:
1. `woocommerce_system_status` for environment, database, theme and active
   plugins.
2. `woocommerce_webhooks` to enumerate configured webhooks and their
   delivery URLs.
3. `woocommerce_orders` to summarize recent orders by status.
4. `woocommerce_products` to summarize products (status, stock, price).
5. `woocommerce_gateways` to confirm which payment gateways are enabled.
6. `woocommerce_shipping` to enumerate shipping zones and methods.

The toolkit does not modify orders, products or settings.

## Security

- Never request that a user paste credentials into the chat. Configure them
  in the MCP runtime environment.
- Never echo `WORDPRESS_APP_PASSWORD`, `WOOCOMMERCE_KEY` or
  `WOOCOMMERCE_SECRET` in your response.
- Treat user lists, order details and webhook URLs as potentially sensitive.
