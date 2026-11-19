import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:bcrypt/bcrypt.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:dotenv/dotenv.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart';
import 'package:shelf_cors_headers/shelf_cors_headers.dart';
import 'package:shelf_router/shelf_router.dart';
import 'package:supabase/supabase.dart';

// ============================================================
// KONFIGURASI
// ============================================================

// Baca .env (lokal) dan environment variable dari hosting (SnapDeploy)
final _env = DotEnv(includePlatformEnvironment: true)..load();

// Koneksi ke Supabase (pakai service_role key, hanya di backend!)
final supabase = SupabaseClient(
  _env['SUPABASE_URL']!,
  _env['SUPABASE_KEY']!,
);

String get _jwtSecret => _env['JWT_SECRET']!;
const _masaToken = Duration(hours: 12);

// Konfigurasi tabel akun. Role "user" = alumni.
// UBAH di sini kalau nama kolom di Supabase berbeda.
class _Akun {
  final String tabel;
  final String id;
  final String email;
  final String password;
  const _Akun(this.tabel, this.id, this.email, this.password);
}

const _daftarAkun = {
  'admin': _Akun('admin', 'id_admin', 'email_admin', 'password_admin'),
  'guru': _Akun('guru', 'id_guru', 'email_guru', 'password_guru'),
  'user': _Akun('user', 'id_user', 'email_user', 'password_user'),
};

// Role yang boleh melihat data semua alumni & dashboard
const _roleStaf = ['guru', 'admin'];

// Kolom yang boleh diisi/diubah alumni (whitelist)
const _fieldAlumni = [
  'tahun_lulus',
  'jurusan',
  'tempattanggal_lahir',
  'no_hp',
  'alamat_lengkap',
];

const _fieldTracer = [
  'status_aktif',
  'pendidikan_terakhir',
  'nama_universitas',
  'program_study',
  'tahun_masuk',
  'nama_perusahaan',
  'posisi_jabatan',
  'bidang_pekerjaan',
  'lokasi_pekerjaan',
];

// ============================================================
// HELPER
// ============================================================

/// Error yang sengaja dilempar dengan kode status tertentu.
class HttpError implements Exception {
  final int status;
  final String pesan;
  HttpError(this.status, this.pesan);
}

Response _json(Object? data, {int status = 200}) {
  return Response(
    status,
    body: jsonEncode(data),
    headers: {'content-type': 'application/json'},
  );
}

Response _ok(Object? data, {int status = 200}) {
  return _json({'status': 'berhasil', 'data': data}, status: status);
}

/// Ambil teks yang sudah di-trim, null kalau kosong.
String? _teks(dynamic v) {
  if (v == null) return null;
  final s = v.toString().trim();
  return s.isEmpty ? null : s;
}

int _angka(String? v, int def, {int min = 1, int max = 100000}) {
  final n = int.tryParse(v ?? '');
  if (n == null) return def;
  return n.clamp(min, max).toInt();
}

Future<Map<String, dynamic>> _bacaBody(Request req) async {
  try {
    final d = jsonDecode(await req.readAsString());
    if (d is Map) return Map<String, dynamic>.from(d);
  } catch (_) {}
  throw HttpError(400, 'Body harus berupa JSON object');
}

/// Ambil hanya field yang diizinkan. String kosong diubah jadi null.
Map<String, dynamic> _ambilField(Map<String, dynamic> body, List<String> boleh) {
  final hasil = <String, dynamic>{};
  for (final k in boleh) {
    if (!body.containsKey(k)) continue;
    final v = body[k];
    hasil[k] = v is String ? (v.trim().isEmpty ? null : v.trim()) : v;
  }
  return hasil;
}

/// Ambil semua baris (supabase membatasi 1000 baris per request).
Future<List<Map<String, dynamic>>> _ambilSemua(String tabel, String kolom) async {
  final hasil = <Map<String, dynamic>>[];
  var dari = 0;
  while (true) {
    final batch = await supabase
        .from(tabel)
        .select(kolom)
        .order('id_user')
        .range(dari, dari + 999);
    hasil.addAll(batch);
    if (batch.length < 1000) break;
    dari += 1000;
  }
  return hasil;
}

// ============================================================
// AUTH (JWT + ROLE)
// ============================================================

String _buatToken(String role, dynamic id) {
  return JWT({'id': id, 'role': role}).sign(
    SecretKey(_jwtSecret),
    expiresIn: _masaToken,
  );
}

/// Cek token di header `Authorization: Bearer TOKEN`.
/// Kalau [role] diisi, role di token harus ada di daftar itu.
/// Mengembalikan payload token: {id, role}.
Map<String, dynamic> _wajibLogin(Request req, [List<String> role = const []]) {
  final header = req.headers['authorization'] ?? '';
  if (!header.toLowerCase().startsWith('bearer ')) {
    throw HttpError(401, 'Token tidak ditemukan. Silakan login.');
  }
  final token = header.substring(7).trim();

  Map<String, dynamic> payload;
  try {
    payload = Map<String, dynamic>.from(
      JWT.verify(token, SecretKey(_jwtSecret)).payload as Map,
    );
  } on JWTExpiredException {
    throw HttpError(401, 'Sesi sudah habis. Silakan login lagi.');
  } on JWTException {
    throw HttpError(401, 'Token tidak valid.');
  } catch (_) {
    throw HttpError(401, 'Token tidak valid.');
  }

  if (role.isNotEmpty && !role.contains(payload['role'])) {
    throw HttpError(403, 'Kamu tidak punya akses ke data ini.');
  }
  return payload;
}

/// Cek password. Mendukung hash bcrypt, dan password lama (teks polos)
/// yang otomatis di-hash saat pertama kali berhasil login.
Future<bool> _cekPassword(_Akun k, Map<String, dynamic> akun, String input) async {
  final tersimpan = akun[k.password]?.toString() ?? '';
  if (tersimpan.isEmpty) return false;

  if (tersimpan.startsWith(r'$2')) {
    try {
      return BCrypt.checkpw(input, tersimpan);
    } catch (_) {
      return false;
    }
  }

  // Password lama (belum di-hash)
  if (tersimpan == input) {
    try {
      await supabase
          .from(k.tabel)
          .update({k.password: BCrypt.hashpw(input, BCrypt.gensalt())})
          .eq(k.id, akun[k.id]);
    } catch (e) {
      print('Gagal upgrade hash di tabel ${k.tabel}: $e');
    }
    return true;
  }
  return false;
}

// ============================================================
// MIDDLEWARE
// ============================================================

/// Tangkap semua error supaya responsnya rapi dan tidak membocorkan detail.
Middleware _tangkapError() {
  return (Handler inner) {
    return (Request req) async {
      try {
        return await inner(req);
      } on HttpError catch (e) {
        return _json({'status': 'gagal', 'error': e.pesan}, status: e.status);
      } catch (e, st) {
        print('ERROR ${req.method} /${req.url}: $e\n$st');
        return _json(
          {'status': 'gagal', 'error': 'Terjadi kesalahan pada server'},
          status: 500,
        );
      }
    };
  };
}

Response _notFound(Request req) {
  return _json({'status': 'gagal', 'error': 'Endpoint tidak ditemukan'}, status: 404);
}

// ============================================================
// ROUTER
// ============================================================

final _router = Router(notFoundHandler: _notFound)
  ..get('/', _rootHandler)
  ..get('/health', _healthHandler)
  // Auth
  ..post('/auth/login', _loginHandler)
  ..post('/auth/register', _registerHandler)
  ..get('/auth/me', _meHandler)
  // Alumni (urutan penting: /me dan /belum-update sebelum /<id>)
  ..get('/alumni', _daftarAlumni)
  ..get('/alumni/me', _profilSaya)
  ..put('/alumni/me', _ubahProfilSaya)
  ..get('/alumni/belum-update', _belumUpdate)
  ..get('/alumni/<id>', _detailAlumni)
  // Tracer study
  ..get('/tracer/me', _tracerSaya)
  ..put('/tracer/me', _ubahTracerSaya)
  ..get('/tracer/<id>', _tracerUser)
  // Dashboard (guru & admin)
  ..get('/dashboard/ringkasan', _dashboardRingkasan)
  ..get('/dashboard/per-jurusan', (Request r) => _rekapPer(r, 'jurusan'))
  ..get('/dashboard/per-tahun', (Request r) => _rekapPer(r, 'tahun_lulus'));

// ============================================================
// HANDLER: UMUM
// ============================================================

Response _rootHandler(Request req) {
  return _json({'pesan': 'Backend DigiTrace jalan!'});
}

Future<Response> _healthHandler(Request req) async {
  try {
    await supabase.from('admin').select('id_admin').limit(1);
    return _json({'status': 'ok', 'database': 'terhubung'});
  } catch (e) {
    print('HEALTH ERROR: $e');
    return _json({'status': 'gagal', 'database': 'tidak terhubung'}, status: 503);
  }
}

// ============================================================
// HANDLER: AUTH
// ============================================================

// POST /auth/login  body: {"email": "...", "password": "..."}
Future<Response> _loginHandler(Request req) async {
  final body = await _bacaBody(req);
  final email = _teks(body['email']);
  final password = body['password']?.toString();

  if (email == null || password == null || password.isEmpty) {
    throw HttpError(400, 'Email dan password wajib diisi');
  }

  // Role ditentukan dari tabel tempat akun ditemukan
  for (final entry in _daftarAkun.entries) {
    final role = entry.key;
    final k = entry.value;

    final akun = await supabase
        .from(k.tabel)
        .select()
        .eq(k.email, email)
        .limit(1)
        .maybeSingle();

    if (akun == null) continue;
    if (!await _cekPassword(k, akun, password)) continue;

    final id = akun[k.id];
    akun.remove(k.password); // jangan kirim password ke frontend
    return _json({
      'status': 'berhasil',
      'role': role,
      'token': _buatToken(role, id),
      'user': akun,
    });
  }

  throw HttpError(401, 'Email atau password salah');
}

// POST /auth/register  (alumni daftar sendiri)
// body: {"nama_user","email_user","password", + opsional field alumni}
Future<Response> _registerHandler(Request req) async {
  final body = await _bacaBody(req);
  final nama = _teks(body['nama_user'] ?? body['nama']);
  final email = _teks(body['email_user'] ?? body['email']);
  final password = body['password']?.toString() ?? '';

  if (nama == null || email == null) {
    throw HttpError(400, 'Nama dan email wajib diisi');
  }
  if (!RegExp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$').hasMatch(email)) {
    throw HttpError(400, 'Format email tidak valid');
  }
  if (password.length < 6 || password.length > 72) {
    throw HttpError(400, 'Password harus 6 sampai 72 karakter');
  }

  // Email harus unik di semua tabel akun
  for (final k in _daftarAkun.values) {
    final ada = await supabase
        .from(k.tabel)
        .select(k.id)
        .eq(k.email, email)
        .limit(1)
        .maybeSingle();
    if (ada != null) throw HttpError(409, 'Email sudah terdaftar');
  }

  final baru = await supabase
      .from('user')
      .insert({
        'nama_user': nama,
        'email_user': email,
        'password_user': BCrypt.hashpw(password, BCrypt.gensalt()),
      })
      .select('id_user, nama_user, email_user')
      .single();

  final profil = _ambilField(body, _fieldAlumni);
  if (profil.isNotEmpty) {
    await supabase.from('alumni').insert({...profil, 'id_user': baru['id_user']});
  }

  return _json({'status': 'berhasil', 'user': baru}, status: 201);
}

// GET /auth/me  -> data akun dari token
Future<Response> _meHandler(Request req) async {
  final auth = _wajibLogin(req);
  final role = auth['role'] as String;
  final k = _daftarAkun[role]!;

  final akun = await supabase
      .from(k.tabel)
      .select()
      .eq(k.id, auth['id'])
      .maybeSingle();
  if (akun == null) throw HttpError(404, 'Akun tidak ditemukan');

  akun.remove(k.password);
  return _json({'status': 'berhasil', 'role': role, 'user': akun});
}

// ============================================================
// HANDLER: ALUMNI
// ============================================================

/// Profil lengkap satu alumni: user + alumni + tracer_study
Future<Map<String, dynamic>> _profilLengkap(dynamic idUser) async {
  final user = await supabase
      .from('user')
      .select('id_user, nama_user, email_user, status_user')
      .eq('id_user', idUser)
      .maybeSingle();
  if (user == null) throw HttpError(404, 'Alumni tidak ditemukan');

  final alumni = await supabase
      .from('alumni')
      .select()
      .eq('id_user', idUser)
      .maybeSingle();
  final tracer = await supabase
      .from('tracer_study')
      .select()
      .eq('id_user', idUser)
      .maybeSingle();

  return {'user': user, 'alumni': alumni, 'tracer_study': tracer};
}

/// Gabungkan baris alumni dengan nama, email, dan status tracer.
Future<List<Map<String, dynamic>>> _gabungkan(List<Map<String, dynamic>> baris) async {
  if (baris.isEmpty) return [];
  final ids = baris.map((b) => b['id_user']).toList();

  final user = await supabase
      .from('user')
      .select('id_user, nama_user, email_user')
      .inFilter('id_user', ids);
  final tracer = await supabase
      .from('tracer_study')
      .select('id_user, status_aktif, nama_universitas, nama_perusahaan')
      .inFilter('id_user', ids);

  final petaUser = {for (final u in user) u['id_user'].toString(): u};
  final petaTracer = {for (final t in tracer) t['id_user'].toString(): t};

  return baris.map((b) {
    final id = b['id_user'].toString();
    final u = petaUser[id];
    final t = petaTracer[id];
    return <String, dynamic>{
      ...b,
      'nama_user': u?['nama_user'],
      'email_user': u?['email_user'],
      'status_aktif': t?['status_aktif'] ?? 'belum_mengisi',
      'nama_universitas': t?['nama_universitas'],
      'nama_perusahaan': t?['nama_perusahaan'],
    };
  }).toList();
}

// GET /alumni?page=1&limit=20&jurusan=RPL&tahun_lulus=2024&status=bekerja&search=budi
Future<Response> _daftarAlumni(Request req) async {
  _wajibLogin(req, _roleStaf);

  final q = req.url.queryParameters;
  final page = _angka(q['page'], 1);
  final limit = _angka(q['limit'], 20, max: 100);

  // Filter yang berasal dari tabel lain dikumpulkan sebagai daftar id
  Set<String>? idBoleh;
  void batasi(Iterable<String> ids) {
    idBoleh = idBoleh == null ? ids.toSet() : idBoleh!.intersection(ids.toSet());
  }

  final cari = _teks(q['search']);
  if (cari != null) {
    final r = await supabase
        .from('user')
        .select('id_user')
        .ilike('nama_user', '%$cari%');
    batasi(r.map((e) => e['id_user'].toString()));
  }

  final status = _teks(q['status']);
  if (status != null) {
    final r = await supabase
        .from('tracer_study')
        .select('id_user')
        .eq('status_aktif', status);
    batasi(r.map((e) => e['id_user'].toString()));
  }

  if (idBoleh != null && idBoleh!.isEmpty) {
    return _json({'status': 'berhasil', 'page': page, 'limit': limit, 'data': []});
  }

  var query = supabase.from('alumni').select();
  final jurusan = _teks(q['jurusan']);
  if (jurusan != null) query = query.eq('jurusan', jurusan);
  final tahun = _teks(q['tahun_lulus']);
  if (tahun != null) query = query.eq('tahun_lulus', tahun);
  if (idBoleh != null) query = query.inFilter('id_user', idBoleh!.toList());

  final dari = (page - 1) * limit;
  final baris = await query.order('id_user').range(dari, dari + limit - 1);

  return _json({
    'status': 'berhasil',
    'page': page,
    'limit': limit,
    'data': await _gabungkan(baris),
  });
}

// GET /alumni/belum-update  -> alumni yang belum mengisi tracer study
Future<Response> _belumUpdate(Request req) async {
  _wajibLogin(req, _roleStaf);

  final q = req.url.queryParameters;
  final page = _angka(q['page'], 1);
  final limit = _angka(q['limit'], 20, max: 100);

  final d = await _muatAlumniDanStatus();
  final belum = d.alumni
      .where((a) =>
          (d.status[a['id_user'].toString()] ?? 'belum_mengisi') == 'belum_mengisi')
      .toList();

  final dari = (page - 1) * limit;
  final potong = dari >= belum.length
      ? <Map<String, dynamic>>[]
      : belum.sublist(dari, min(dari + limit, belum.length));

  return _json({
    'status': 'berhasil',
    'page': page,
    'limit': limit,
    'total': belum.length,
    'data': await _gabungkan(potong),
  });
}

// GET /alumni/<id>  (guru/admin)
Future<Response> _detailAlumni(Request req, String id) async {
  _wajibLogin(req, _roleStaf);
  return _ok(await _profilLengkap(id));
}

// GET /alumni/me  (alumni)
Future<Response> _profilSaya(Request req) async {
  final auth = _wajibLogin(req, ['user']);
  return _ok(await _profilLengkap(auth['id']));
}

// PUT /alumni/me  (alumni ubah profil sendiri)
Future<Response> _ubahProfilSaya(Request req) async {
  final auth = _wajibLogin(req, ['user']);
  final id = auth['id'];
  final body = await _bacaBody(req);

  final data = _ambilField(body, _fieldAlumni);
  final nama = _teks(body['nama_user']);
  if (data.isEmpty && nama == null) {
    throw HttpError(400, 'Tidak ada data yang diubah');
  }

  if (nama != null) {
    await supabase.from('user').update({'nama_user': nama}).eq('id_user', id);
  }

  if (data.isNotEmpty) {
    final ada = await supabase
        .from('alumni')
        .select('id_user')
        .eq('id_user', id)
        .maybeSingle();
    if (ada == null) {
      await supabase.from('alumni').insert({...data, 'id_user': id});
    } else {
      await supabase.from('alumni').update(data).eq('id_user', id);
    }
  }

  return _ok(await _profilLengkap(id));
}

// ============================================================
// HANDLER: TRACER STUDY
// ============================================================

// GET /tracer/me
Future<Response> _tracerSaya(Request req) async {
  final auth = _wajibLogin(req, ['user']);
  final data = await supabase
      .from('tracer_study')
      .select()
      .eq('id_user', auth['id'])
      .maybeSingle();
  return _ok(data);
}

// PUT /tracer/me  (alumni isi / perbarui status)
Future<Response> _ubahTracerSaya(Request req) async {
  final auth = _wajibLogin(req, ['user']);
  final id = auth['id'];
  final body = await _bacaBody(req);

  final data = _ambilField(body, _fieldTracer);
  if (data.isEmpty) throw HttpError(400, 'Tidak ada data yang diubah');

  final ada = await supabase
      .from('tracer_study')
      .select('id_user')
      .eq('id_user', id)
      .maybeSingle();

  if (ada == null) {
    if (_teks(data['status_aktif']) == null) {
      throw HttpError(400, 'status_aktif wajib diisi');
    }
    await supabase.from('tracer_study').insert({...data, 'id_user': id});
  } else {
    await supabase.from('tracer_study').update(data).eq('id_user', id);
  }

  final hasil = await supabase
      .from('tracer_study')
      .select()
      .eq('id_user', id)
      .maybeSingle();
  return _ok(hasil);
}

// GET /tracer/<id>  (guru/admin)
Future<Response> _tracerUser(Request req, String id) async {
  _wajibLogin(req, _roleStaf);
  final data = await supabase
      .from('tracer_study')
      .select()
      .eq('id_user', id)
      .maybeSingle();
  return _ok(data);
}

// ============================================================
// HANDLER: DASHBOARD
// ============================================================

Future<({List<Map<String, dynamic>> alumni, Map<String, String> status})>
    _muatAlumniDanStatus() async {
  final alumni = await _ambilSemua('alumni', 'id_user, jurusan, tahun_lulus');
  final tracer = await _ambilSemua('tracer_study', 'id_user, status_aktif');
  final status = <String, String>{
    for (final t in tracer)
      t['id_user'].toString(): _teks(t['status_aktif']) ?? 'belum_mengisi',
  };
  return (alumni: alumni, status: status);
}

// GET /dashboard/ringkasan
Future<Response> _dashboardRingkasan(Request req) async {
  _wajibLogin(req, _roleStaf);
  final d = await _muatAlumniDanStatus();

  final perStatus = <String, int>{};
  for (final a in d.alumni) {
    final s = d.status[a['id_user'].toString()] ?? 'belum_mengisi';
    perStatus[s] = (perStatus[s] ?? 0) + 1;
  }

  return _ok({'total_alumni': d.alumni.length, 'per_status': perStatus});
}

// GET /dashboard/per-jurusan  dan  /dashboard/per-tahun
Future<Response> _rekapPer(Request req, String kunci) async {
  _wajibLogin(req, _roleStaf);
  final d = await _muatAlumniDanStatus();

  final kelompok = <String, Map<String, int>>{};
  for (final a in d.alumni) {
    final nama = _teks(a[kunci]) ?? 'tidak_diketahui';
    final s = d.status[a['id_user'].toString()] ?? 'belum_mengisi';
    final peta = kelompok.putIfAbsent(nama, () => <String, int>{});
    peta[s] = (peta[s] ?? 0) + 1;
  }

  final hasil = kelompok.entries.map((e) {
    final total = e.value.values.fold<int>(0, (x, y) => x + y);
    return <String, dynamic>{kunci: e.key, 'total': total, 'per_status': e.value};
  }).toList()
    ..sort((x, y) => x[kunci].toString().compareTo(y[kunci].toString()));

  return _ok(hasil);
}

// ============================================================
// MAIN
// ============================================================

void main() async {
  // Pastikan environment lengkap sebelum server jalan
  const wajib = ['SUPABASE_URL', 'SUPABASE_KEY', 'JWT_SECRET'];
  final kurang = wajib.where((k) => (_env[k] ?? '').isEmpty).toList();
  if (kurang.isNotEmpty) {
    stderr.writeln('Environment belum lengkap: ${kurang.join(', ')}');
    exit(1);
  }
  if (_env['JWT_SECRET']!.length < 32) {
    stderr.writeln('JWT_SECRET minimal 32 karakter');
    exit(1);
  }

  final handler = const Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(corsHeaders())
      .addMiddleware(_tangkapError())
      .addHandler(_router.call);

  // Port dari hosting kalau ada, kalau tidak pakai 8080
  final port = int.parse(Platform.environment['PORT'] ?? '8080');
  final server = await serve(handler, InternetAddress.anyIPv4, port);
  print('Server jalan di http://localhost:${server.port}');
}