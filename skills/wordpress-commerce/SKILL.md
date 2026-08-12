---
name: wordpress-commerce
description: Diagnose configured WordPress and WooCommerce installations through read-only REST API tools.
---

# WordPress and WooCommerce Diagnostics

The MCP server can inspect one configured WordPress/WooCommerce environment through environment variables.

## WordPress

Configure `WORDPRESS_BASE_URL`. For authenticated plugin listing also configure `WORDPRESS_USERNAME` and `WORDPRESS_APP_PASSWORD`.

Use `wordpress_rest_index` to inspect namespaces/routes and `wordpress_plugins` for plugin state.

## WooCommerce

Configure `WOOCOMMERCE_BASE_URL`, `WOOCOMMERCE_KEY`, and `WOOCOMMERCE_SECRET` with read-only REST API credentials.

Use `woocommerce_system_status` for environment diagnostics and `woocommerce_webhooks` to inspect webhook configuration.

Never ask the user to paste credentials into tool arguments. Credentials belong in the client's MCP environment configuration.
