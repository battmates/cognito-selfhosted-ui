<header class="mb-6 text-center">
    <h1 class="text-2xl font-semibold">Set up your authenticator app</h1>
    <p class="mt-2 text-sm text-slate-500">Scan the QR code with your authenticator app or enter the secret key manually.</p>
</header>

<?php if (!empty($errors ?? [])): ?>
    <div class="mb-4 rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">
        <?php foreach (($errors ?? []) as $error): ?>
            <p><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
        <?php endforeach; ?>
    </div>
<?php endif; ?>

<?php include __DIR__ . '/../components/debug.php'; ?>

<div class="mb-6 flex flex-col items-center space-y-4">
    <?php if (!empty($qr_code ?? '')): ?>
        <img src="<?= htmlspecialchars($qr_code, ENT_QUOTES, 'UTF-8'); ?>" alt="QR code" class="h-48 w-48" />
    <?php endif; ?>
    <div class="rounded bg-slate-100 px-4 py-2 text-sm font-mono">
        <?= htmlspecialchars($secret ?? '', ENT_QUOTES, 'UTF-8'); ?>
    </div>
</div>

<form method="post" class="space-y-4">
    <input type="hidden" name="_token" value="<?= htmlspecialchars($csrf_token ?? '', ENT_QUOTES, 'UTF-8'); ?>">
    <div>
        <label for="mfa_code" class="mb-1 block text-sm font-medium">6-digit code</label>
        <input id="mfa_code" name="mfa_code" type="text" inputmode="numeric" autocomplete="one-time-code" required class="w-full rounded border border-slate-300 px-3 py-2 focus:border-indigo-500 focus:outline-none focus:ring" />
    </div>
    <button type="submit" class="w-full rounded bg-indigo-600 px-4 py-2 text-white hover:bg-indigo-500">Verify and continue</button>
</form>
