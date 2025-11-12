import { file } from 'zod/v4';
import { initSupabase } from './utils/supabase_initialize';
import { getSupabase } from './utils/supabaseClient';

export default {
  async fetch(request: Request, env: any) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "https://webapp-bka.pages.dev",
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Refresh-Token,x-refresh-token,x-user-role',
      'Content-Type': 'application/json; charset=UTF-8',
    };

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
      const supabase = initSupabase(env);
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

          // 生の入力値を取得
          const rawEmail = body.email;
          const rawPassword = body.password;

          // サニタイズして安全な値に変換
          const email = sanitizeEmail(rawEmail);
          const password = sanitizePassword(rawPassword);
          if (!email || !password) {
            return new Response(JSON.stringify({ error: 'メールとパスワードを入力してください' }), {
              status: 400,
              headers: corsHeaders,
            });
          }

          // --- Supabase Service Role Key で管理者クライアントを作成 ---
          const supabaseAdmin = getSupabase(env);

          // --- ① 既に同じメールが存在するかチェック ---
          const { data: userList, error: listError } = await supabaseAdmin.auth.admin.listUsers();

          if (listError) {
            console.error('User list error:', listError.message);
            return new Response(JSON.stringify({ error: 'ユーザー確認中にエラーが発生しました。' }), {
              status: 500,
              headers: corsHeaders,
            });
          }

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
              emailRedirectTo: 'http:/webapp-bka.pages.dev/auth.html',
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
      // --- ログイン ---
      if (path === '/login' && request.method === 'POST') {
        const body = await request.json();

        // 生の入力値を取得
        const rawEmail = body.email;
        const rawPassword = body.password;

        // サニタイズして安全な値に変換
        const email = sanitizeEmail(rawEmail);
        const password = sanitizePassword(rawPassword);
        if (!email || !password) return new Response(JSON.stringify({ error: 'メールとパスワードを入力してください' }), { status: 400, headers: corsHeaders });

        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) return new Response(JSON.stringify({ error: error.message }), { status: 401, headers: corsHeaders });

        return new Response(
          JSON.stringify({
            success: true,
            user: data.user,
            access_token: data.session.access_token,
            refresh_token: data.session.refresh_token,
          }),
          { headers: corsHeaders }
        );
      }
      // --- ログイン者確認 ---
      if (path === '/me' && request.method === 'GET') {
        const authHeader = request.headers.get("Authorization");
        const refreshHeader = request.headers.get("X-Refresh-Token"); // refresh_tokenをヘッダーで受け取る想定
        if (!authHeader) {
          return new Response(JSON.stringify({ loggedIn: false, message: "No access token" }), {
            status: 401,
            headers: corsHeaders,
          });
        }

        const token = authHeader.replace("Bearer ", "").trim();
        const { data, error } = await supabase.auth.getUser(token);

        // ===== access_token が有効な場合 =====
        if (data?.user && !error) {
          return new Response(
            JSON.stringify({ loggedIn: true, user: data.user }),
            { headers: corsHeaders }
          );
        }

        // ===== access_token が無効 && refresh_token がある場合 =====
        if (refreshHeader) {
          const refresh_token = refreshHeader.trim();
          const { data: refreshed, error: refreshError } = await supabase.auth.refreshSession({ refresh_token });

          const session = refreshed?.session;
          const user = refreshed?.user;

          if (session && user && !refreshError) {
            return new Response(
              JSON.stringify({
                loggedIn: true,
                user,
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

        // ===== どちらも無効 =====
        return new Response(JSON.stringify({ loggedIn: false, message: "Invalid or expired token" }), {
          status: 401,
          headers: corsHeaders,
        });
      }

      if (path === '/request-password-reset' && request.method === 'POST') {
        try {
          const { email } = await request.json();
          if (!email) {
            return new Response(JSON.stringify({ error: 'メールアドレスを入力してください。' }), {
              status: 400,
              headers: corsHeaders,
            });
          }

          // anonキーでOK（認証不要のため）
          const supabaseClient = initSupabase(env);

          const { error } = await supabaseClient.auth.resetPasswordForEmail(email, {
            redirectTo: 'http://webapp-bka.pages.dev/reset-confirm.html',
          });

          if (error) {
            console.error('Reset error:', error.message);
            return new Response(JSON.stringify({ error: error.message }), {
              status: 400,
              headers: corsHeaders,
            });
          }

          return new Response(
            JSON.stringify({ success: true, message: 'パスワードリセット用のメールを送信しました。' }),
            { headers: corsHeaders }
          );

        } catch (err) {
          console.error('Reset worker error:', err);
          return new Response(JSON.stringify({ error: '内部エラーが発生しました。' }), {
            status: 500,
            headers: corsHeaders,
          });
        }
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
        const { id, imagePath, access_token, refresh_token } = await request.json();
        if (!id || !access_token || !refresh_token) return new Response(JSON.stringify({ error: 'id, access_token, refresh_token が必要です' }), { status: 400, headers: corsHeaders });

        // セッション設定
        await supabase.auth.setSession({ access_token, refresh_token });

        // DB 削除
        const { error: deleteError } = await supabase.from('hazard_pin').delete().eq('id', id);
        if (deleteError) return new Response(JSON.stringify({ error: deleteError.message }), { status: 500, headers: corsHeaders });

        // Storage 削除
        if (imagePath) {
          const url = new URL(imagePath);
          // URLパスを分解して "pin-images/" の後ろを取得
          const parts = url.pathname.split('/');
          const pinImagesIndex = parts.indexOf('pin-images');
          const filePath = parts.slice(pinImagesIndex + 1).join('/');
          console.log("削除対象ファイル:", filePath);
          const supabaseAdmin = getSupabase(env); // service_role key
          const { error: storageError } = await supabaseAdmin.storage.from('pin-images').remove([filePath]);
          if (storageError) return new Response(JSON.stringify({ warning: 'DBは削除済みだが画像削除失敗', storageError: storageError.message }), { status: 200, headers: corsHeaders });
        }
        return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
      }
      // --- リアルタイム監視（SSE） ---
      if (path === '/realtime' && request.method === 'GET') {
        const supabase = getSupabase(env);
        let channel: any;
        let controllerRef: ReadableStreamDefaultController | null = null;

        const stream = new ReadableStream({
          start(controller) {
            controllerRef = controller;
            const encoder = new TextEncoder();

            channel = supabase.channel('hazard_pin_changes')
              .on(
                'postgres_changes',
                { event: 'INSERT', schema: 'public', table: 'hazard_pin' },
                (payload) => {
                  const msg = `data: ${JSON.stringify(payload.new)}\n\n`;
                  controller.enqueue(encoder.encode(msg));
                }
              )
              .subscribe();

            controller.enqueue(encoder.encode(`data: {"status":"connected"}\n\n`));
          },

          cancel(reason) {
            console.log('SSE接続終了:', reason);
            if (channel) {
              supabase.removeChannel(channel);
            }
            controllerRef = null;
          },
        });

        return new Response(stream, {
          headers: {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache, no-transform',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*',
          },
        });
      }
      // --- デフォルト応答 ---
      return new Response(JSON.stringify({ message: 'Worker is running', path }), { status: 200, headers: corsHeaders });
    } catch (err: any) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
    }
  },
};
