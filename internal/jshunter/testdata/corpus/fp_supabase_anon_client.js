// assets/supabase-client-Dq4nW8xR.js
// The anon key is the public half of a Supabase project: its JWT payload
// carries {"role":"anon"} and every table it can reach is gated by Row Level
// Security. Supabase ships it in the browser bundle on purpose.
import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = "https://qhdvmzkulnbpwscyaefg.supabase.co";
const SUPABASE_ANON_KEY =
  "%%JSHT032%%";

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
    storageKey: "acme.auth.token",
    flowType: "pkce"
  },
  global: {
    headers: {
      "x-client-info": "acme-web/2026.9.3",
      apikey: SUPABASE_ANON_KEY
    }
  },
  realtime: { params: { eventsPerSecond: 5 } },
  db: { schema: "public" }
});

// Storage and functions endpoints derived from the project ref.
const endpoints = {
  rest: `${SUPABASE_URL}/rest/v1`,
  auth: `${SUPABASE_URL}/auth/v1`,
  storage: `${SUPABASE_URL}/storage/v1`,
  functions: `${SUPABASE_URL}/functions/v1`,
  realtime: `${SUPABASE_URL.replace("https://", "wss://")}/realtime/v1`
};

async function signInWithOtp(email) {
  const { error } = await supabase.auth.signInWithOtp({
    email,
    options: { emailRedirectTo: "https://acme-corp.dev/auth/callback" }
  });
  if (error) throw new Error(`[auth] otp request failed: ${error.message}`);
  return { sent: true };
}

async function loadCatalogue({ page = 0, size = 24 } = {}) {
  const from = page * size;
  const { data, error, count } = await supabase
    .from("products")
    .select("id,slug,title,price_cents,thumb_url", { count: "exact" })
    .eq("published", true)
    .order("released_at", { ascending: false })
    .range(from, from + size - 1);
  if (error) throw new Error(`[catalogue] ${error.code}: ${error.message}`);
  return { rows: data ?? [], total: count ?? 0, page, size };
}

function subscribeToStock(productId, onChange) {
  const channel = supabase
    .channel(`stock:${productId}`)
    .on(
      "postgres_changes",
      { event: "UPDATE", schema: "public", table: "stock", filter: `product_id=eq.${productId}` },
      (payload) => onChange(payload.new)
    )
    .subscribe((status) => {
      if (status === "CHANNEL_ERROR") console.warn("[realtime] channel error", productId);
    });
  return () => supabase.removeChannel(channel);
}

export { supabase, endpoints, SUPABASE_URL, SUPABASE_ANON_KEY, signInWithOtp, loadCatalogue, subscribeToStock };
