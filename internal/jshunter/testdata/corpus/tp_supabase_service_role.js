// assets/admin-import-Dn6kV3wQ.js
// Bulk import screen for the back office. It was built against the service
// role key because the anon key could not bypass Row Level Security — and the
// bundle it lives in is served to every signed-in user, not just admins.
import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = "https://qhdvmzkulnbpwscyaefg.supabase.co";

// Payload decodes to {"iss":"supabase","ref":"...","role":"service_role",...}
const SUPABASE_SERVICE_ROLE_KEY =
  "%%JSHT037%%";

const admin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
  global: { headers: { "x-client-info": "acme-admin/2026.9.3" } },
  db: { schema: "public" }
});

const IMPORT_COLUMNS = ["sku", "title", "price_cents", "stock", "published"];
const BATCH_SIZE = 500;

function parseCsv(text) {
  const [head, ...rows] = text.trim().split(/\r?\n/);
  const cols = head.split(",").map((c) => c.trim());
  const missing = IMPORT_COLUMNS.filter((c) => !cols.includes(c));
  if (missing.length) throw new Error(`missing columns: ${missing.join(", ")}`);
  return rows.map((line, i) => {
    const cells = line.split(",");
    const row = {};
    cols.forEach((c, j) => (row[c] = cells[j]?.trim() ?? ""));
    row.price_cents = Number(row.price_cents);
    row.stock = Number(row.stock);
    row.published = row.published === "true";
    if (!row.sku) throw new Error(`row ${i + 2}: sku is required`);
    if (!Number.isFinite(row.price_cents)) throw new Error(`row ${i + 2}: bad price`);
    return row;
  });
}

async function importRows(rows, onProgress) {
  const results = { inserted: 0, failed: [] };
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const batch = rows.slice(i, i + BATCH_SIZE);
    const { error, count } = await admin
      .from("products")
      .upsert(batch, { onConflict: "sku", count: "exact", ignoreDuplicates: false });
    if (error) results.failed.push({ from: i, error: error.message });
    else results.inserted += count ?? batch.length;
    onProgress?.(Math.min(i + BATCH_SIZE, rows.length) / rows.length);
  }
  return results;
}

async function purgeUnlisted(skus) {
  const { error } = await admin.from("products").delete().not("sku", "in", `(${skus.join(",")})`);
  if (error) throw new Error(`purge failed: ${error.message}`);
}

export { admin, parseCsv, importRows, purgeUnlisted, IMPORT_COLUMNS, SUPABASE_SERVICE_ROLE_KEY };
