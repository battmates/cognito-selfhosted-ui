<?php if (!empty($debug ?? [])): ?>
    <details class="mb-4 rounded border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800">
        <summary class="cursor-pointer font-semibold">Debug details</summary>
        <pre class="mt-2 overflow-auto whitespace-pre-wrap"><?= htmlspecialchars(json_encode($debug, JSON_PRETTY_PRINT), ENT_QUOTES, 'UTF-8'); ?></pre>
    </details>
<?php endif; ?>
