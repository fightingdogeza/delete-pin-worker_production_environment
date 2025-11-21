import { file } from 'zod/v4';
import { initSupabase } from './utils/supabase_initialize';
import { getSupabase } from './utils/supabaseClient';

export default {
  async fetch(request: Request, env: any) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "https://chi-map.pages.dev",
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Refresh-Token,x-refresh-token,x-user-role',
      'Content-Type': 'application/json; charset=UTF-8',
    };
    const supabase = initSupabase(env);
    const supabaseAdmin = getSupabase(env);
    // ファイル名サニタイズ
    function sanitizeFileName(fileName: string) {
      const ext = fileName.split('.').pop();
      const random = Math.random().toString(36).substring(2, 8); // ランダム6文字
      const base = fileName.split('.').slice(0, -1).join('.');
      const uuid = crypto.randomUUID();
      const safeBase = base.replace(/[^a-zA-Z0-9_-]/g, '_');
      return `${safeBase}_${random}_${uuid}.${ext}`;
    }
    // 通常のテキスト入力用（タイトル・説明など）
    function sanitizeText(input: string) {
      return input.replace(/[<>"'`;(){}]/g, "");
    }

    // メールアドレス用：不正文字を除外するが、@と.は残す
    function sanitizeEmail(input: string) {
      return input.replace(/[^a-zA-Z0-9@._+-]/g, "");
    }

    // パスワード用：制御文字（改行やタブなど）だけ除外
    function sanitizePassword(input: string) {
      return input.replace(/[\r\n\t]/g, "");
    }

    try {
      const url = new URL(request.url);
      const path = url.pathname;
      // プリフライト対応
      if (request.method === 'OPTIONS') {
        return new Response('OK', { headers: corsHeaders });
      }
      // Supabase 初期化
      // --- Supabase情報取得 ---
      if (path === '/init-supabase') {
        return new Response(
          JSON.stringify({
            supabaseUrl: env.SUPABASE_URL,
            supabaseAnonKey: env.SUPABASE_ANON_KEY,
          }),
          { headers: corsHeaders }
        );
      }
      // --- ユーザー登録 ---
      if (path === '/register' && request.method === 'POST') {
        try {
          const body = await request.json();

          console.log(body);
          // 生の入力値を取得
          const rawEmail = body.email;
          const rawPassword = body.password;

          // サニタイズして安全な値に変換
          const email = sanitizeEmail(rawEmail);
          const password = sanitizePassword(rawPassword);

          console.log("Signup request:", { email, password });

          if (!email || !password) {
            return new Response(JSON.stringify({ error: 'メールとパスワードを入力してください' }), {
              status: 400,
              headers: corsHeaders,
            });
          }
          // ---既に同じメールが存在するかチェック ---
          const { data: userList, error: listError } = await supabaseAdmin.auth.admin.listUsers();

          if (listError) {
            console.error('User list error:', listError.message);
            return new Response(JSON.stringify({ error: 'ユーザー確認中にエラーが発生しました。' }), {
              status: 500,
              headers: corsHeaders,
            });
          }
          if (password.length < 6) {
            return new Response(JSON.stringify({ error: "パスワードは6文字以上で入力してください" }), { status: 400, headers: corsHeaders });
          }

          //通常のanonキーでは合致しているか探せない
          const alreadyExists = userList.users.some((u) => u.email?.toLowerCase() === email.toLowerCase());
          if (alreadyExists) {
            return new Response(JSON.stringify({ error: 'このメールアドレスは既に登録されています。' }), {
              status: 400,
              headers: corsHeaders,
            });
          }

          // ---新規登録（確認メール送信） ---
          const { data, error } = await supabase.auth.signUp({
            email,
            password,
            options: {
              emailRedirectTo: 'https:/chi-map.pages.dev/auth',
            },
          });

          if (error) {
            console.error('Signup error:', error.message);
            return new Response(JSON.stringify({ error: error.message }), {
              status: 400,
              headers: corsHeaders,
            });
          }

          return new Response(
            JSON.stringify({
              success: true,
              message: '確認メールを送信しました。メール内リンクをクリックしてログインしてください。',
            }),
            { headers: corsHeaders },
          );

        } catch (err) {
          console.error('Register worker error:', err);
          return new Response(JSON.stringify({ error: '内部エラーが発生しました。' }), {
            status: 500,
            headers: corsHeaders,
          });
        }
      }
      if (path === '/login' && request.method === 'POST') {
        const body = await request.json();

        // 生の入力値を取得
        const rawEmail = body.email;
        const rawPassword = body.password;

        // サニタイズして安全な値に変換
        const email = sanitizeEmail(rawEmail);
        const password = sanitizePassword(rawPassword);

        if (!email || !password) {
          return new Response(
            JSON.stringify({ error: 'メールとパスワードを入力してください' }),
            { status: 400, headers: corsHeaders }
          );
        }

        // サービスロールキーを使ったSupabaseクライアントでログイン
        const { data, error } = await supabaseAdmin.auth.signInWithPassword({ email, password });

        if (error) {
          return new Response(
            JSON.stringify({ error: error.message }),
            { status: 401, headers: corsHeaders }
          );
        }

        // セッションが null の場合はメール未確認や設定による可能性
        const access_token = data.session?.access_token || null;
        const refresh_token = data.session?.refresh_token || null;

        // レスポンスにメッセージを追加して状況を明確化
        let message = "ログイン成功";
        if (!access_token) {
          message = "メール未確認またはセッション未作成のためトークンは発行されません";
        }

        return new Response(
          JSON.stringify({
            success: !!data.user,
            user: data.user,
            access_token,
            refresh_token,
            message,
          }),
          { headers: corsHeaders }
        );
      }

      // --- ログイン者確認 ---
      if (path === '/me' && request.method === 'GET') {
        const authHeader = request.headers.get("Authorization");
        const refreshHeader = request.headers.get("X-Refresh-Token"); // refresh_tokenをヘッダーで受け取る想定

        if (!authHeader) {
          return new Response(
            JSON.stringify({ loggedIn: false, message: "No access token" }),
            { status: 401, headers: corsHeaders }
          );
        }

        const token = authHeader.replace("Bearer ", "").trim();
        const { data, error } = await supabase.auth.getUser(token);

        if (data?.user && !error) {
          const user = data.user;

          const { data: roleData, error: roleError } = await supabaseAdmin
            .from("app_users")
            .select("role")
            .eq("email", user.email)
            .single();

          // 取得に失敗したら "user" をデフォルトに
          const role = roleError || !roleData ? "user" : roleData.role;

          return new Response(
            JSON.stringify({
              loggedIn: true,
              user: {
                id: user.id,
                email: user.email,
                role: role, // ← 追加
              },
            }),
            { headers: corsHeaders }
          );
        }
        if (refreshHeader) {
          const refresh_token = refreshHeader.trim();
          const { data: refreshed, error: refreshError } = await supabase.auth.refreshSession({ refresh_token });

          const session = refreshed?.session;
          const user = refreshed?.user;

          if (session && user && !refreshError) {
            const { data: roleData, error: roleError } = await supabase
              .from("app_users")
              .select("role")
              .eq("id", user.id)
              .single();

            const role = roleError || !roleData ? "user" : roleData.role;

            return new Response(
              JSON.stringify({
                loggedIn: true,
                user: {
                  id: user.id,
                  email: user.email,
                  role,
                },
                new_access_token: session.access_token,
                new_refresh_token: session.refresh_token,
              }),
              { headers: corsHeaders }
            );
          }

          // refreshSessionに失敗した場合
          return new Response(
            JSON.stringify({
              loggedIn: false,
              message: "Failed to refresh session or invalid refresh_token",
            }),
            { status: 401, headers: corsHeaders }
          );
        }

        return new Response(
          JSON.stringify({ loggedIn: false, message: "Invalid or expired token" }),
          { status: 401, headers: corsHeaders }
        );
      }
      if (path === "/filter-pins" && request.method === "POST") {
        const { categories, radius, center } = await request.json();

        if (!categories || !Array.isArray(categories)) {
          return new Response(JSON.stringify({ error: "categories は配列である必要があります" }), {
            status: 400,
            headers: corsHeaders,
          });
        }

        let query = supabase
          .from("hazard_pin")
          .select("*, categories(name)");
        const numericCategories = categories.map(c => Number(c));
        query = query.in("category_id", numericCategories);

        // --- カテゴリ絞り込み ---
        if (categories.length > 0) {
          query = query.in("category_id", categories);
        }

        // --- 半径検索を使用する場合 ---
        if (radius && center?.lat && center?.lng) {
          const radiusMeters = radius * 1000;

          // SQL 条件を追加
          query = query.filter(
            "id",
            "in",
            supabase.rpc("filter_by_distance", {
              target_lat: center.lat,
              target_lng: center.lng,
              radius_meters: radiusMeters
            })
          );
        }

        const { data, error } = await query;

        if (error) {
          return new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: corsHeaders,
          });
        }

        return new Response(JSON.stringify(data), { headers: corsHeaders });
      }

      // --- ピン投稿 ---
      if (path === '/post-pin' && request.method === 'POST') {
        const formData = await request.formData();
        const title = sanitizeText(formData.get("title")?.toString() || "");
        const description = sanitizeText(formData.get("description")?.toString() || "");
        const category_id = formData.get("category_id")?.toString();
        const lat = parseFloat(formData.get("lat")?.toString() || "0");
        const lng = parseFloat(formData.get("lng")?.toString() || "0");
        const uid = formData.get("uid")?.toString();

        if (!title || !category_id || !uid) return new Response(JSON.stringify({ error: "必須項目が足りません" }), { status: 400, headers: corsHeaders });

        let image_path: string | null = null;
        const imageFile = formData.get("image") as File;

        if (imageFile && imageFile.size > 0) {
          const arrayBuffer = await imageFile.arrayBuffer();
          const blob = new Blob([arrayBuffer], { type: imageFile.type });
          const safeFileName = sanitizeFileName(imageFile.name);
          const filePath = `user_uploads/${safeFileName}`;
          const { error: uploadError } = await supabase.storage
            .from("pin-images")
            .upload(filePath, blob, { contentType: imageFile.type, metadata: { owner_uid: uid } });
          if (uploadError) throw new Error(uploadError.message);
          image_path = `${env.SUPABASE_URL}/storage/v1/object/public/pin-images/${filePath}`;
        }
        const { data, error } = await supabase.from("hazard_pin").insert([{
          title,
          description,
          category_id,
          lat,
          lng,
          uid,
          image_path,
          created_at: new Date().toISOString()
        }]).select();

        if (error) return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: corsHeaders });

        return new Response(JSON.stringify({ success: true, pin: data[0] }), { headers: corsHeaders });
      }

      // --- 全ピン取得 ---
      if (path === '/get-all-pins') {
        const { data, error } = await supabase.from('hazard_pin').select(`*, categories(name)`);
        if (error) return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: corsHeaders });
        return new Response(JSON.stringify(data), { headers: corsHeaders });
      }

      // --- ユーザー別ピン取得 ---
      if (path === '/get-user-pins' && request.method === 'POST') {
        const { userId } = await request.json();
        if (!userId) return new Response(JSON.stringify({ error: 'userIdが必要です' }), { status: 400, headers: corsHeaders });

        const { data, error } = await supabase.from('hazard_pin').select('*, categories(name)').eq('uid', userId);
        if (error) return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: corsHeaders });
        return new Response(JSON.stringify(data), { headers: corsHeaders });
      }

      // --- ピン削除 ---
      if (path === '/delete-pin' && request.method === 'POST') {
        const { id, imagePath, access_token, refresh_token, role } =
          await request.json();
        if (!id || !access_token || !refresh_token) return new Response(JSON.stringify({ error: 'id, access_token, refresh_token が必要です' }), { status: 400, headers: corsHeaders });

        // セッション設定
        if (role === "admin") {
          // DB 削除
          const { error: deleteError } = await supabaseAdmin.from('hazard_pin').delete().eq('id', id);
          if (deleteError) return new Response(JSON.stringify({ error: deleteError.message }), { status: 500, headers: corsHeaders });
        } else {
          await supabase.auth.setSession({ access_token, refresh_token });
          // DB 削除
          const { error: deleteError } = await supabase.from('hazard_pin').delete().eq('id', id);
          if (deleteError) return new Response(JSON.stringify({ error: deleteError.message }), { status: 500, headers: corsHeaders });
        }

        // Storage 削除
        if (imagePath) {
          const url = new URL(imagePath);
          // URLパスを分解して "pin-images/" の後ろを取得
          const parts = url.pathname.split('/');
          const pinImagesIndex = parts.indexOf('pin-images');
          const filePath = parts.slice(pinImagesIndex + 1).join('/');
          console.log("削除対象ファイル:", filePath);
          const supabaseAdmin = getSupabase(env);
          const { error: storageError } = await supabaseAdmin.storage.from('pin-images').remove([filePath]);
          if (storageError) return new Response(JSON.stringify({ warning: 'DBは削除済みだが画像削除失敗', storageError: storageError.message }), { status: 200, headers: corsHeaders });
        }
        return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
      }
      return new Response(JSON.stringify({ message: 'Worker is running', path }), { status: 200, headers: corsHeaders });
    } catch (err: any) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
    }
  },
};
