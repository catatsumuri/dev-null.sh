<?php

declare(strict_types=1);

use App\Models\Device;
use App\Models\PushSubscription;
use App\Models\User;
use Illuminate\Session\DatabaseSessionHandler;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;

beforeEach(function (): void {
    config(['session.driver' => 'database']);
});

it('requires authentication to revoke browser sessions', function (): void {
    $this->deleteJson(route('browser-session.destroy'))->assertUnauthorized();
});

it('revokes all browser sessions and remember cookies while preserving apps and other accounts', function (): void {
    $user = User::factory()->create(['remember_token' => 'old-token']);
    $other = User::factory()->create(['remember_token' => 'other-token']);
    $device = Device::factory()->for($user)->create();
    PushSubscription::factory()->count(2)->create(['user_id' => $user->id]);
    $otherSubscription = PushSubscription::factory()->create(['user_id' => $other->id]);
    $guard = Auth::guard('web');
    $cookie = $guard->getRecallerName();
    $sessionIds = [Str::random(40), Str::random(40)];

    foreach ([...$sessionIds, 'other-account-session', 'guest-session'] as $id) {
        DB::table('sessions')->insert([
            'id' => $id,
            'user_id' => match ($id) {
                'other-account-session' => $other->id,
                'guest-session' => null,
                default => $user->id,
            },
            'payload' => base64_encode(json_encode([$guard->getName() => $user->id], JSON_THROW_ON_ERROR)),
            'last_activity' => now()->getTimestamp(),
        ]);
    }

    // An already running request must not recreate a session deleted by revocation.
    $handler = new DatabaseSessionHandler(DB::connection(), 'sessions', 120);
    $payload = $handler->read($sessionIds[0]);
    expect($payload)->toBeString();
    assert(is_string($payload));

    $this->actingAs($user)->delete(route('browser-session.destroy'))->assertRedirectToRoute('home');

    $this->assertGuest();
    $this->assertDatabaseMissing('sessions', ['user_id' => $user->id]);
    $this->assertDatabaseHas('sessions', ['id' => 'other-account-session', 'user_id' => $other->id]);
    $this->assertDatabaseHas('sessions', ['id' => 'guest-session', 'user_id' => null]);
    expect($user->refresh()->remember_token)->not->toBe('old-token')
        ->and($user->pushSubscriptions()->count())->toBe(0)
        ->and($other->refresh()->remember_token)->toBe('other-token');
    $this->assertModelExists($device);
    $this->assertModelExists($otherSubscription);

    $handler->write($sessionIds[0], $payload);
    $this->assertDatabaseMissing('sessions', ['id' => $sessionIds[0]]);

    Route::middleware(['web', 'auth'])->get('/browser-session-test', fn (): string => 'authenticated');
    Auth::forgetGuards();
    $this->withCookie(config('session.cookie'), $sessionIds[1])
        ->withCookie($cookie, $user->id.'|old-token|')
        ->get('/browser-session-test')->assertRedirectToRoute('home');
    $this->assertGuest();
});

it('refuses unsupported session storage without partially revoking the account', function (): void {
    config(['session.driver' => 'array']);
    $user = User::factory()->create(['remember_token' => 'old-token']);
    $subscription = PushSubscription::factory()->create(['user_id' => $user->id]);

    $this->actingAs($user)->deleteJson(route('browser-session.destroy'))->assertServiceUnavailable();

    $this->assertAuthenticatedAs($user);
    expect($user->refresh()->remember_token)->toBe('old-token');
    $this->assertModelExists($subscription);
});
