--TEST--
blake3_derive_key() — KDF mode (derive key from context + material)
--SKIPIF--
<?php if ( !extension_loaded('blake3') ) die( 'skip blake3 extension not loaded' ); ?>
--FILE--
<?php
  $uPass = 0;
  $uFail = 0;

  function fnVerify( string $sLabel, mixed $mActual, mixed $mExpected ) : void
  {
    global $uPass, $uFail;

    if ( $mActual === $mExpected ) { $uPass++; echo "OK  $sLabel\n"; }
    else { $uFail++; echo "FAIL $sLabel\n  got:    $mActual\n  expect: $mExpected\n"; }
  }

  $sDk = blake3_derive_key( 'my-app-v1', 'secret-material' );
  fnVerify( 'derive_hex_len', strlen($sDk), 64 );
  fnVerify( 'derive_hex_fmt', preg_match('/^[0-9a-f]{64}$/', $sDk), 1 );

  fnVerify( 'derive_deterministic', blake3_derive_key('my-app-v1', 'secret-material') === $sDk, TRUE );
  fnVerify( 'derive_diff_ctx',      blake3_derive_key('other-app', 'secret-material') !== $sDk, TRUE );
  fnVerify( 'derive_diff_mat',      blake3_derive_key('my-app-v1', 'other-material')  !== $sDk, TRUE );

  try { blake3_derive_key( '', 'material' ); fnVerify( 'derive_empty_ctx', FALSE, TRUE ); }
  catch ( ValueError $oE ) { fnVerify( 'derive_empty_ctx', strpos($oE->getMessage(), 'empty') !== FALSE, TRUE ); }

  try { blake3_derive_key( 'ctx', '' ); fnVerify( 'derive_empty_mat', FALSE, TRUE ); }
  catch ( ValueError $oE ) { fnVerify( 'derive_empty_mat', strpos($oE->getMessage(), 'empty') !== FALSE, TRUE ); }

  $sUk = blake3_derive_key( 'app', 'material' );
  fnVerify( 'derive_unicode_len', strlen($sUk), 64 );
  fnVerify( 'derive_unicode_fmt', preg_match('/^[0-9a-f]{64}$/', $sUk), 1 );

  $sLk = blake3_derive_key( str_repeat('ctx', 1000), str_repeat('mat', 10000) );
  fnVerify( 'derive_long_len', strlen($sLk), 64 );

  $sDk16 = blake3_derive_key( 'ctx', 'mat', 16 );
  fnVerify( 'derive_16_len',    strlen($sDk16), 32 );
  fnVerify( 'derive_16_unique', $sDk16 !== $sDk, TRUE );

  $sDk64 = blake3_derive_key( 'ctx', 'mat', 64 );
  fnVerify( 'derive_64_len',    strlen($sDk64), 128 );
  fnVerify( 'derive_64_unique', $sDk64 !== $sDk, TRUE );

  try { blake3_derive_key( 'ctx', 'mat', 0 ); fnVerify( 'derive_zero_len', FALSE, TRUE ); }
  catch ( ValueError $oE ) { fnVerify( 'derive_zero_len', strpos($oE->getMessage(), 'greater') !== FALSE, TRUE ); }

  try { blake3_derive_key( 'ctx', 'mat', 100000000 ); fnVerify( 'derive_huge_len', FALSE, TRUE ); }
  catch ( ValueError $oE ) { fnVerify( 'derive_huge_len', strpos($oE->getMessage(), '64 MB') !== FALSE, TRUE ); }

  $sDkRaw = blake3_derive_key( 'my-app-v1', 'secret-material', 32, TRUE );
  fnVerify( 'derive_raw_len', strlen($sDkRaw), 32 );
  fnVerify( 'derive_raw_hex', bin2hex($sDkRaw), $sDk );

  echo "\n$uPass passed, $uFail failed\n";
?>
--EXPECT--
OK  derive_hex_len
OK  derive_hex_fmt
OK  derive_deterministic
OK  derive_diff_ctx
OK  derive_diff_mat
OK  derive_empty_ctx
OK  derive_empty_mat
OK  derive_unicode_len
OK  derive_unicode_fmt
OK  derive_long_len
OK  derive_16_len
OK  derive_16_unique
OK  derive_64_len
OK  derive_64_unique
OK  derive_zero_len
OK  derive_huge_len
OK  derive_raw_len
OK  derive_raw_hex

18 passed, 0 failed
