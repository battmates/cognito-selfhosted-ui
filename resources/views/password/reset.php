<header class="mb-6 text-center">
    <h1 class="text-2xl font-semibold">Create a new password</h1>
    <p class="mt-2 text-sm text-slate-500">Use the code from your email to set a new password.</p>
</header>

<?php if (!empty($success ?? '')): ?>
    <div class="mb-4 rounded border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-700">
        <?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?>
    </div>
<?php endif; ?>

<?php if (!empty($errors ?? [])): ?>
    <div class="mb-4 rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">
        <?php foreach (($errors ?? []) as $error): ?>
            <p><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
        <?php endforeach; ?>
    </div>
<?php endif; ?>

<form method="post" class="space-y-4">
    <input type="hidden" name="_token" value="<?= htmlspecialchars($csrf_token ?? '', ENT_QUOTES, 'UTF-8'); ?>">
    <div>
        <label for="email" class="mb-1 block text-sm font-medium">Email address</label>
        <input id="email" name="email" type="email" required value="<?= htmlspecialchars($email ?? '', ENT_QUOTES, 'UTF-8'); ?>" class="w-full rounded border border-slate-300 px-3 py-2 focus:border-indigo-500 focus:outline-none focus:ring" />
    </div>
    <div>
        <label for="code" class="mb-1 block text-sm font-medium">Verification code</label>
        <input id="code" name="code" type="text" inputmode="numeric" required class="w-full rounded border border-slate-300 px-3 py-2 focus:border-indigo-500 focus:outline-none focus:ring" />
    </div>
    <div>
        <label for="password" class="mb-1 block text-sm font-medium">New password</label>
        <input id="password" name="password" type="password" required class="w-full rounded border border-slate-300 px-3 py-2 focus:border-indigo-500 focus:outline-none focus:ring" />
    </div>
    <div>
        <label for="password_confirmation" class="mb-1 block text-sm font-medium">Confirm new password</label>
        <input id="password_confirmation" name="password_confirmation" type="password" required class="w-full rounded border border-slate-300 px-3 py-2 focus:border-indigo-500 focus:outline-none focus:ring" />
    </div>
    <button type="submit" class="w-full rounded bg-indigo-600 px-4 py-2 text-white hover:bg-indigo-500">Update password</button>
</form>

<p class="mt-6 text-center text-sm text-slate-500">
    Back to <a href="/oauth2/authorize" class="text-indigo-600 hover:text-indigo-500">login</a>
</p>
