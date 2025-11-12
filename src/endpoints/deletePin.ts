import { getSupabase } from '../utils/supabaseClient';

export async function deletePin(request: Request, env: any) {
  const supabase = getSupabase(env);
  const body = await request.json();
  const { pinId, userId, role } = body;

  if (!pinId) {
    return new Response(JSON.stringify({ error: 'pinIdがありません' }), { status: 400 });
  }

  if (role !== 'admin') {
    const { data: target } = await supabase
      .from('hazard_pin')
      .select('uid')
      .eq('id', pinId)
      .single();

    if (!target || target.uid !== userId) {
      return new Response(JSON.stringify({ error: '権限がありません' }), { status: 403 });
    }
  }

  const { error } = await supabase.from('hazard_pin').delete().eq('id', pinId);
  if (error) {
    return new Response(JSON.stringify({ error: error.message }), { status: 500 });
  }

  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
