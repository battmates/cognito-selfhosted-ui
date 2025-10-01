<header class="mb-6 text-center">
    <h1 class="text-2xl font-semibold">Sign in</h1>
    <p class="mt-2 text-sm text-slate-500">AWS Cognito self-hosted UI placeholder</p>
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
        <label for="username" class="mb-1 block text-sm font-medium">Username or email</label>
        <input id="username" name="username" type="text" required value="<?= htmlspecialchars($prefill_username ?? '', ENT_QUOTES, 'UTF-8'); ?>" class="w-full rounded border border-slate-300 px-3 py-2 focus:border-indigo-500 focus:outline-none focus:ring" />
    </div>
    <div>
        <label for="password" class="mb-1 block text-sm font-medium">Password</label>
        <input id="password" name="password" type="password" required class="w-full rounded border border-slate-300 px-3 py-2 focus:border-indigo-500 focus:outline-none focus:ring" />
    </div>
    <div class="flex items-center justify-between text-sm">
        <a href="/forgot-password" class="text-indigo-600 hover:text-indigo-500">Forgot password?</a>
        <a href="/register" class="text-indigo-600 hover:text-indigo-500">Create account</a>
    </div>
    <button type="submit" class="w-full rounded bg-indigo-600 px-4 py-2 text-white hover:bg-indigo-500">Continue</button>
</form>
