<header class="mb-6 text-center">
    <h1 class="text-2xl font-semibold">Create your account</h1>
    <p class="mt-2 text-sm text-slate-500">Sign up to access your account with AWS Cognito.</p>
</header>

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
        <input id="email" name="email" type="email" required value="<?= htmlspecialchars($values['email'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" class="w-full rounded border border-slate-300 px-3 py-2 focus:border-indigo-500 focus:outline-none focus:ring" />
    </div>
    <div>
        <label for="password" class="mb-1 block text-sm font-medium">Password</label>
        <input id="password" name="password" type="password" required class="w-full rounded border border-slate-300 px-3 py-2 focus:border-indigo-500 focus:outline-none focus:ring" />
    </div>
    <div>
        <label for="password_confirmation" class="mb-1 block text-sm font-medium">Confirm password</label>
        <input id="password_confirmation" name="password_confirmation" type="password" required class="w-full rounded border border-slate-300 px-3 py-2 focus:border-indigo-500 focus:outline-none focus:ring" />
    </div>
    <button type="submit" class="w-full rounded bg-indigo-600 px-4 py-2 text-white hover:bg-indigo-500">Create account</button>
</form>

<p class="mt-6 text-center text-sm text-slate-500">
    Already have an account? <a href="/oauth2/authorize" class="text-indigo-600 hover:text-indigo-500">Sign in</a>
</p>
