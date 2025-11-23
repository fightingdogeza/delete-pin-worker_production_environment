import { initSupabase } from './utils/supabase_initialize';
import { getSupabase } from './utils/supabaseClient';

/**
 * Revised Cloudflare Worker for Supabase usage with optimizations to avoid
 * accidental Realtime / connection explosions and heavy DB operations.
 *
 * Key changes:
 * - Cache Supabase clients in globalThis to avoid recreating per-request clients
 * - Avoid `select(..., foreign_table(...))` joins; return only hazard_pin fields
 * - Replace RPC distance-filter approach with a lightweight bounding-box + JS Haversine
 * - Keep Realtime disabled in workers (if your utils support that, ensure they do)
 * - Fix email redirect URL and minor security improvements
 */

// Cache clients on the global scope so cold starts still share the same instances
declare const globalThis: any;

function getCachedClient(env: any) {
  // use cached client if present
  if (!globalThis._supabaseClient) {
    globalThis._supabaseClient = initSupabase(env);
  }
  return globalThis._supabaseClient;
}
function getCachedAdminClient(env: any) {
  if (!globalThis._supabaseAdminClient) {
    globalThis._supabaseAdminClient = getSupabase(env);
  }
  return globalThis._supabaseAdminClient;
}

// ----- Sanitizers -----
function sanitizeFileName(fileName: string) {
  const ext = (fileName || '').split('.').pop() || '';
  const base = (fileName || '').split('.').slice(0, -1).join('.') || 'file';
  const random = Math.random().toString(36).substring(2, 8);
  const uuid = typeof crypto !== 'undefined' && (crypto as any).randomUUID ? (crypto as any).randomUUID() : `${Date.now()}`;
  const safeBase = base.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 128);
  return `${safeBase}_${random}_${uuid}.${ext}`;
}
function sanitizeText(input: string) {
  return (input || '').replace(/[<>"'`;(){}]/g, '').slice(0, 2000);
}
function sanitizeEmail(input: string) {
  return (input || '').replace(/[^a-zA-Z0-9@._+-]/g, '').slice(0, 256);
}
function sanitizePassword(input: string) {
  return (input || '').replace(/[\r\n\t]/g, '').slice(0, 256);
}

function haversineDistanceMeters(lat1: number, lng1: number, lat2: number, lng2: number) {
  const toRad = (d: number) => (d * Math.PI) / 180;
  const R = 6371000; // metres
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lng2 - lng1);
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// ----- Bounding-box for rough DB filter -----
function boundingBox(lat: number, lng: number, radiusMeters: number) {
  // ~111.32 km per degree latitude
  const latDelta = radiusMeters / 111320;
  // longitude degree distance depends on latitude
  const lngDelta = radiusMeters / (111320 * Math.cos((lat * Math.PI) / 180) || 1);
  return {
    minLat: lat - latDelta,
    maxLat: lat + latDelta,
    minLng: lng - lngDelta,
    maxLng: lng + lngDelta,
  };
}

export default {
  async fetch(request: Request, env: any) {
    const corsHeaders = {
      'Access-Control-Allow-Origin': 'https://chi-map.pages.dev',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Refresh-Token,x-refresh-token,x-user-role',
      'Content-Type': 'application/json; charset=UTF-8',
    };

    try {
      const url = new URL(request.url);
      const path = url.pathname;

      // Preflight
      if (request.method === 'OPTIONS') return new Response('OK', { headers: corsHeaders });

      // instantiate cached clients
      const supabase = getCachedClient(env);
      const supabaseAdmin = getCachedAdminClient(env);

      // --- init-supabase ---
      if (path === '/init-supabase') {
        return new Response(JSON.stringify({ supabaseUrl: env.SUPABASE_URL, supabaseAnonKey: env.SUPABASE_ANON_KEY }), { headers: corsHeaders });
      }

      // --- register ---
      if (path === '/register' && request.method === 'POST') {
        try {
          const body = await request.json();
          const rawEmail = body.email;
          const rawPassword = body.password;
          const email = sanitizeEmail(rawEmail);
          const password = sanitizePassword(rawPassword);

          if (!email || !password) return new Response(JSON.stringify({ error: 'メールとパスワードを入力してください' }), { status: 400, headers: corsHeaders });
          if (password.length < 6) return new Response(JSON.stringify({ error: 'パスワードは6文字以上で入力してください' }), { status: 400, headers: corsHeaders });

          // check if email exists using admin client listing (costly but necessary for duplicate check)
          const { data: userList, error: listError } = await supabaseAdmin.auth.admin.listUsers();
          if (listError) {
            console.error('User list error:', listError.message);
            return new Response(JSON.stringify({ error: 'ユーザー確認中にエラーが発生しました。' }), { status: 500, headers: corsHeaders });
          }
          const alreadyExists = userList.users.some((u: any) => u.email?.toLowerCase() === email.toLowerCase());
          if (alreadyExists) return new Response(JSON.stringify({ error: 'このメールアドレスは既に登録されています。' }), { status: 400, headers: corsHeaders });

          const { data, error } = await supabase.auth.signUp({ email, password, options: { emailRedirectTo: 'https://chi-map.pages.dev/auth' } });
          if (error) {
            console.error('Signup error:', error.message);
            return new Response(JSON.stringify({ error: error.message }), { status: 400, headers: corsHeaders });
          }

          return new Response(JSON.stringify({ success: true, message: '確認メールを送信しました。メール内リンクをクリックしてログインしてください。' }), { headers: corsHeaders });
        } catch (err) {
          console.error('Register worker error:', err);
          return new Response(JSON.stringify({ error: '内部エラーが発生しました。' }), { status: 500, headers: corsHeaders });
        }
      }

      // --- login ---
      if (path === '/login' && request.method === 'POST') {
        const body = await request.json();
        const email = sanitizeEmail(body.email);
        const password = sanitizePassword(body.password);
        if (!email || !password) return new Response(JSON.stringify({ error: 'メールとパスワードを入力してください' }), { status: 400, headers: corsHeaders });

        const { data, error } = await supabaseAdmin.auth.signInWithPassword({ email, password });
        if (error) return new Response(JSON.stringify({ error: error.message }), { status: 401, headers: corsHeaders });

        const access_token = data.session?.access_token || null;
        const refresh_token = data.session?.refresh_token || null;
        let message = 'ログイン成功';
        if (!access_token) message = 'メール未確認またはセッション未作成のためトークンは発行されません';

        return new Response(JSON.stringify({ success: !!data.user, user: data.user, access_token, refresh_token, message }), { headers: corsHeaders });
      }

      // --- me ---
      if (path === '/me' && request.method === 'GET') {
        const authHeader = request.headers.get('Authorization');
        const refreshHeader = request.headers.get('X-Refresh-Token');
        if (!authHeader && !refreshHeader) return new Response(JSON.stringify({ loggedIn: false, message: 'No access token' }), { status: 401, headers: corsHeaders });

        if (authHeader) {
          const token = authHeader.replace('Bearer ', '').trim();
          const { data, error } = await supabase.auth.getUser(token);
          if (data?.user && !error) {
            const user = data.user;
            const { data: roleData, error: roleError } = await supabaseAdmin.from('app_users').select('role').eq('email', user.email).single();
            const role = roleError || !roleData ? 'user' : roleData.role;
            return new Response(JSON.stringify({ loggedIn: true, user: { id: user.id, email: user.email, role } }), { headers: corsHeaders });
          }
        }

        if (refreshHeader) {
          const refresh_token = refreshHeader.trim();
          const { data: refreshed, error: refreshError } = await supabase.auth.refreshSession({ refresh_token });
          const session = refreshed?.session;
          const user = refreshed?.user;
          if (session && user && !refreshError) {
            const { data: roleData, error: roleError } = await supabase.from('app_users').select('role').eq('id', user.id).single();
            const role = roleError || !roleData ? 'user' : roleData.role;
            return new Response(JSON.stringify({ loggedIn: true, user: { id: user.id, email: user.email, role }, new_access_token: session.access_token, new_refresh_token: session.refresh_token }), { headers: corsHeaders });
          }
          return new Response(JSON.stringify({ loggedIn: false, message: 'Failed to refresh session or invalid refresh_token' }), { status: 401, headers: corsHeaders });
        }

        return new Response(JSON.stringify({ loggedIn: false, message: 'Invalid or expired token' }), { status: 401, headers: corsHeaders });
      }

      // --- filter-pins: improved to avoid heavy DB/RPC use ---
      if (path === '/filter-pins' && request.method === 'POST') {
        const { categories, radius, center } = await request.json();
        if (!categories || !Array.isArray(categories)) return new Response(JSON.stringify({ error: 'categories は配列である必要があります' }), { status: 400, headers: corsHeaders });

        // Build a reduced DB query using bounding box to reduce scanned rows
        let query = await supabase.from('hazard_pin').select('id,title,description,category_id,lat,lng,uid,image_path,created_at');
        // category filter
        if (categories.length > 0) {
          const numericCategories = categories.map((c: any) => Number(c)).filter((n: number) => !Number.isNaN(n));
          if (numericCategories.length > 0) query = query.in('category_id', numericCategories);
        }
        // radius filter via bounding box + JS Haversine
        let radiusMeters = null;
        if (radius && center?.lat && center?.lng) {
          radiusMeters = Number(radius) * 1000;
          const box = boundingBox(center.lat, center.lng, radiusMeters);
          query = query.gte('lat', box.minLat).lte('lat', box.maxLat).gte('lng', box.minLng).lte('lng', box.maxLng);
        }

        const { data, error } = await query;
        if (error) return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: corsHeaders });

        let results = data || [];
        if (radiusMeters && center) {
          results = results.filter((p: any) => {
            const dist = haversineDistanceMeters(center.lat, center.lng, Number(p.lat), Number(p.lng));
            return dist <= radiusMeters;
          });
        }

        return new Response(JSON.stringify(results), { headers: corsHeaders });
      }

      // --- post-pin: unchanged semantics but safer upload naming ---
      if (path === '/post-pin' && request.method === 'POST') {
        const formData = await request.formData();
        const title = sanitizeText(formData.get('title')?.toString() || '');
        const description = sanitizeText(formData.get('description')?.toString() || '');
        const category_id = formData.get('category_id')?.toString();
        const lat = parseFloat(formData.get('lat')?.toString() || '0');
        const lng = parseFloat(formData.get('lng')?.toString() || '0');
        const uid = formData.get('uid')?.toString();

        if (!title || !category_id || !uid) return new Response(JSON.stringify({ error: '必須項目が足りません' }), { status: 400, headers: corsHeaders });

        let image_path = null;
        const imageFile = formData.get('image') as File;
        if (imageFile && (imageFile as any).size > 0) {
          const arrayBuffer = await (imageFile as File).arrayBuffer();
          const blob = new Blob([arrayBuffer], { type: (imageFile as File).type || 'application/octet-stream' });
          const safeFileName = sanitizeFileName((imageFile as File).name || 'upload');
          const filePath = `user_uploads/${safeFileName}`;
          const { error: uploadError } = await supabase.storage.from('pin-images').upload(filePath, blob, { contentType: (imageFile as File).type, metadata: { owner_uid: uid } });
          if (uploadError) throw new Error(uploadError.message);
          image_path = `${env.SUPABASE_URL}/storage/v1/object/public/pin-images/${filePath}`;
        }

        const { data, error } = await supabase.from('hazard_pin').insert([{
          title, description, category_id, lat, lng, uid, image_path, created_at: new Date().toISOString()
        }]).select();

        if (error) return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: corsHeaders });
        return new Response(JSON.stringify({ success: true, pin: data[0] }), { headers: corsHeaders });
      }

      // --- get-all-pins: return lightweight fields only ---
      if (path === '/get-all-pins') {
        const { data, error } = await supabase.from('hazard_pin').select('id,title,description,category_id,lat,lng,uid,image_path,created_at,categories(name)');
        if (error) return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: corsHeaders });
        return new Response(JSON.stringify({data}), { headers: corsHeaders });
      }

      // --- get-user-pins ---
      if (path === '/get-user-pins') {
        const { userId } = await request.json();
        if (!userId) return new Response(JSON.stringify({ error: 'userIdが必要です' }), { status: 400, headers: corsHeaders });
        const { data, error } = await supabase.from('hazard_pin').select('id,title,description,category_id,lat,lng,uid,image_path,created_at');
        if (error) return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: corsHeaders });
        return new Response(JSON.stringify(data), { headers: corsHeaders });
      }

      // --- delete-pin ---
      if (path === '/delete-pin' && request.method === 'POST') {
        const { id, imagePath, access_token, refresh_token, role } = await request.json();
        if (!id) return new Response(JSON.stringify({ error: 'id が必要です' }), { status: 400, headers: corsHeaders });

        // Use admin client for admin deletion only; otherwise set session for user client
        if (role === 'admin') {
          const { error: deleteError } = await supabaseAdmin.from('hazard_pin').delete().eq('id', id);
          if (deleteError) return new Response(JSON.stringify({ error: deleteError.message }), { status: 500, headers: corsHeaders });
        } else {
          if (!access_token || !refresh_token) return new Response(JSON.stringify({ error: 'access_token, refresh_token が必要です' }), { status: 400, headers: corsHeaders });
          await supabase.auth.setSession({ access_token, refresh_token });
          const { error: deleteError } = await supabase.from('hazard_pin').delete().eq('id', id);
          if (deleteError) return new Response(JSON.stringify({ error: deleteError.message }), { status: 500, headers: corsHeaders });
        }

        // storage delete
        if (imagePath) {
          try {
            const urlObj = new URL(imagePath);
            const parts = urlObj.pathname.split('/');
            const pinImagesIndex = parts.indexOf('pin-images');
            if (pinImagesIndex >= 0) {
              const filePath = parts.slice(pinImagesIndex + 1).join('/');
              const { error: storageError } = await supabaseAdmin.storage.from('pin-images').remove([filePath]);
              if (storageError) return new Response(JSON.stringify({ warning: 'DBは削除済みだが画像削除失敗', storageError: storageError.message }), { status: 200, headers: corsHeaders });
            }
          } catch (e) {
            console.error('storage delete error', e);
          }
        }

        return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
      }

      return new Response(JSON.stringify({ message: 'Worker is running', path }), { status: 200, headers: corsHeaders });
    } catch (err: any) {
      return new Response(JSON.stringify({ error: err.message || String(err) }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
  }
};
