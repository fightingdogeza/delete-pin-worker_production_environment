import { createClient } from '@supabase/supabase-js';

export interface Env {
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
}

// 👇 Supabase 初期化関数を export
export function initSupabase(env: Env) {
  return createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, {
    realtime: { enabled: false } as any,
  });
}

// 👇 fetch 関数はCORS対応のまま残す
export default {
  async fetch(request: Request, env: Env) {
    const headers = {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': 'https://chi-map.pages.dev',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers });
    }

    if (new URL(request.url).pathname === '/init-supabase') {
      return new Response(
        JSON.stringify({
          supabaseUrl: env.SUPABASE_URL,
          supabaseAnonKey: env.SUPABASE_ANON_KEY
        }),
        { headers }
      );
    }

    return new Response('Not found', { status: 404, headers });
  },
};
