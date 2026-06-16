# ACA-AOL Purchase Payment

Modul import Purchase Payment / Pembayaran Pembelian ke Accurate Online.

## Railway Variables

Wajib:

```env
AO_CLIENT_ID=...
AO_CLIENT_SECRET=...
AO_REDIRECT_URI=https://subdomain.aca-aol.id/oauth/callback
AO_SCOPE=purchase_payment_save
AO_PP_SAVE_PATH=/api/purchase-payment/bulk-save.do
JWT_SECRET=isi_random_panjang_min_32_karakter
SECRET_KEY=isi_random_panjang
ADMIN_EMAIL=admin@aca-aol.id
ADMIN_PASSWORD=password_admin_yang_aman
```

## Admin Panel

Buka:

```text
/admin
```

Fitur:
- tambah customer
- edit customer
- reset database terdaftar
- aktif/nonaktif customer
- kuota database

## Template Excel

Download dari tombol Download Template di aplikasi.

Header wajib minimal:
- TRANSDATE
- VENDORNO
- BANKNO
- CHEQUEAMOUNT
- INVOICENO
- PAYMENTAMOUNT
