<header class="mb-6 text-center">
    <h1 class="text-2xl font-semibold">Choose a verification method</h1>
    <p class="mt-2 text-sm text-slate-500">Select how you would like to receive your verification codes.</p>
</header>

<?php if (!empty($errors ?? [])): ?>
    <div class="mb-4 rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">
        <?php foreach (($errors ?? []) as $error): ?>
            <p><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
        <?php endforeach; ?>
    </div>
<?php endif; ?>

<?php include __DIR__ . '/../components/debug.php'; ?>

<form method="post" class="space-y-4">
    <input type="hidden" name="_token" value="<?= htmlspecialchars($csrf_token ?? '', ENT_QUOTES, 'UTF-8'); ?>">
    <div class="space-y-3">
        <?php foreach (($options ?? []) as $option): ?>
            <label class="flex cursor-pointer items-center space-x-3 rounded border border-slate-200 p-3 hover:border-indigo-400">
                <input type="radio" name="mfa_choice" value="<?= htmlspecialchars($option['value'], ENT_QUOTES, 'UTF-8'); ?>" class="h-4 w-4" required>
                <span class="text-sm font-medium text-slate-700"><?= htmlspecialchars($option['label'], ENT_QUOTES, 'UTF-8'); ?></span>
            </label>
        <?php endforeach; ?>
    </div>
    <button type="submit" class="w-full rounded bg-indigo-600 px-4 py-2 text-white hover:bg-indigo-500">Continue</button>
</form>
