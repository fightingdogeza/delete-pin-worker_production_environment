import { getSupabase } from '../utils/supabaseClient';

export async function getAllPins(env: any) {
  const supabase = getSupabase(env);

  const { data, error } = await supabase
    .from('hazard_pin')
    .select('*, categories(name)');

  if (error) {
    return new Response(JSON.stringify({ error: error.message }), { status: 500 });
  }

  return new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json' },
  });
}
