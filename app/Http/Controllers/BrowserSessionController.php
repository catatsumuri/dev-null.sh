<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

final readonly class BrowserSessionController
{
    public function destroy(Request $request): RedirectResponse
    {
        abort_unless(Config::string('session.driver') === 'database', 503, 'Browser session revocation requires database sessions.');

        $user = $request->user();
        assert($user instanceof User);

        DB::transaction(function () use ($user): void {
            // Share the account lock with push enrollment so existing subscriptions are removed together.
            $account = User::query()->whereKey($user->id)->lockForUpdate()->firstOrFail();
            $account->forceFill([
                'remember_token' => Str::random(60),
            ])->save();
            $connection = config('session.connection');
            assert(is_string($connection) || $connection === null);

            DB::connection($connection)
                ->table(Config::string('session.table'))
                ->where('user_id', $user->id)
                ->delete();
            $account->pushSubscriptions()->delete();
        });

        // The token was rotated above; avoid replacing it again with the stale authenticated model.
        Auth::guard('web')->logoutCurrentDevice();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return to_route('home');
    }
}
