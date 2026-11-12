import 'dart:convert';
import 'dart:io';

import 'package:dotenv/dotenv.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart';
import 'package:shelf_router/shelf_router.dart';
import 'package:supabase/supabase.dart';

// Baca .env (lokal) dan environment variable dari hosting
final _env = DotEnv(includePlatformEnvironment: true)..load();

// Koneksi ke Supabase
final supabase = SupabaseClient(
  _env['SUPABASE_URL']!,
  _env['SUPABASE_KEY']!,
);

// Nama kolom login & password di tiap tabel.
// UBAH di sini kalau nama kolom di Supabase berbeda.
const _kolomLogin = {
  'admin': {'login': 'email_admin', 'password': 'password_admin'},
  'guru': {'login': 'email_guru', 'password': 'password_guru'},
  'user': {'login': 'email_user', 'password': 'password_user'},
};

// Daftar endpoint
final _router = Router()
  ..get('/', _rootHandler)
  ..get('/alumni', _alumniHandler)
  ..post('/auth/login', _loginHandler);

// Helper: kirim balasan JSON
Response _json(Object data, {int status = 200}) {
  return Response(
    status,
    body: jsonEncode(data),
    headers: {'content-type': 'application/json'},
  );
}

// GET /  -> cek backend hidup
Response _rootHandler(Request req) {
  return _json({'pesan': 'Backend DigiTrace jalan!'});
}

// GET /alumni  -> daftar semua alumni
Future<Response> _alumniHandler(Request req) async {
  try {
    final data = await supabase.from('alumni').select();
    return _json(data);
  } catch (e, st) {
    print('ERROR ALUMNI: $e\n$st');
    return _json({'error': e.toString()}, status: 500);
  }
}

// POST /auth/login  -> cek email + password di tabel admin, guru, user
Future<Response> _loginHandler(Request req) async {
  try {
    final body = jsonDecode(await req.readAsString()) as Map<String, dynamic>;
    final email = body['email'] as String?;
    final password = body['password'] as String?;

    if (email == null || password == null) {
      return _json({'error': 'Email dan password wajib diisi'}, status: 400);
    }

    final errors = <String>[];

    // Role ditentukan dari tabel tempat akun ditemukan
    for (final role in _kolomLogin.keys) {
      final kolom = _kolomLogin[role]!;
      try {
        final akun = await supabase
            .from(role)
            .select()
            .eq(kolom['login']!, email)
            .eq(kolom['password']!, password)
            .maybeSingle();

        print('Cek tabel $role: ${akun == null ? "tidak ketemu" : "ketemu"}');

        if (akun != null) {
          akun.remove(kolom['password']); // jangan kirim password ke frontend
          return _json({'status': 'berhasil', 'role': role, 'user': akun});
        }
      } catch (e) {
        print('ERROR di tabel $role: $e');
        errors.add('tabel $role: $e');
      }
    }

    // Kalau ada tabel yang error, tampilkan supaya gampang dicari
    if (errors.isNotEmpty) {
      return _json({'error': errors}, status: 500);
    }

    return _json({'error': 'Email atau password salah'}, status: 401);
  } catch (e, st) {
    print('ERROR LOGIN: $e\n$st');
    return _json({'error': e.toString()}, status: 500);
  }
}

void main() async {
  // Cek .env (hapus bagian ini kalau sudah beres)
  print('File .env ada? ${File('.env').existsSync()}');
  print('SUPABASE_URL terbaca? ${_env['SUPABASE_URL'] != null}');
  print('SUPABASE_KEY terbaca? ${_env['SUPABASE_KEY'] != null}');

  final handler = const Pipeline()
      .addMiddleware(logRequests())
      .addHandler(_router.call);

  // Port dari hosting kalau ada, kalau tidak pakai 8080
  final port = int.parse(Platform.environment['PORT'] ?? '8080');
  final server = await serve(handler, InternetAddress.anyIPv4, port);
  print('Server jalan di http://localhost:${server.port}');
}