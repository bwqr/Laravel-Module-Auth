<?php


namespace App\Modules\Auth\Tests\Feature;


use App\Modules\Core\Tests\TestCase;
use App\Modules\Core\User;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;


class AuthModuleTest extends TestCase
{
    private $user;

    public function setUp(): void
    {
        parent::setUp();

        $this->user = factory(User::class)->make();
    }

    public function testRoutes(): void
    {
        $this->assertFalse($this->checkRoute($this->authRoute . 'register', 'post'));
        $this->assertTrue($this->checkRoute($this->authRoute . 'login', 'post'));
        $this->assertTrue($this->checkRoute($this->authRoute . 'reset-password', 'post'));
        $this->assertTrue($this->checkRoute($this->authRoute . 'logout'));
        $this->assertTrue($this->checkRoute($this->authRoute . 'is-authenticated'));
    }

    public function testCorrectLogin(): void
    {
        $password = Str::random(random_int(8, 20));

        $user = factory(User::class)->create([
            'password' => Hash::make($password)
        ]);

        $input = [
            'email' => $user->email,
            'password' => $password
        ];

        $this->post($this->authRoute . 'login', $input)->assertStatus(200);

        $this->assertAuthenticatedAs($user, 'api');
    }

    public function testWrongLogin(): void
    {
        $password = Str::random(random_int(8, 20));

        $user = factory(User::class)->create([
            'password' => Hash::make($password)
        ]);

        $input = [
            'email' => $user->email,
            'password' => $password . Str::random(random_int(1, 5))
        ];

        $this->post($this->authRoute . 'login', $input)->assertStatus(401);
        $this->assertFalse($this->isAuthenticated('api'));
    }

    public function testGuestLogout(): void
    {
        $this->assertFalse($this->isAuthenticated('api'));

        $this->get($this->authRoute . 'logout')->assertStatus(302);

        $this->assertFalse($this->isAuthenticated('api'));
    }

    public function testAuthLogout(): void
    {
        Config::set('jwt.secret', 'test-suite-jwt-secret');

        $user = factory(User::class)->create();

        $token = auth('api')->login($user);

        $this->withHeader('Authorization', "Bearer {$token}")
            ->getJson($this->authRoute . 'logout')
            ->assertStatus(200);

        $this->expectException(TokenBlacklistedException::class);

        JWTAuth::setToken($token);
        JWTAuth::authenticate();
    }

    public function testIsAuthenticated(): void
    {
        $response = $this->actingAs($this->user)->getJson($this->authRoute . 'is-authenticated');

        $response->assertStatus(200);

        $response->assertExactJson(['authenticated' => true]);
    }

    public function testIsNotAuthenticated(): void
    {
        $response = $this->getJson($this->authRoute . 'is-authenticated');

        $response->assertStatus(200);

        $response->assertExactJson(['authenticated' => false]);
    }

    public function testResetPassword()
    {
        $user = factory(User::class)->create();

        $password = Str::random(random_int(8, 20));

        $input = [
            'password' => $password,
            'password_confirmation' => $password
        ];

        $this->actingAs($user)->post($this->authRoute . 'reset-password', $input)->assertStatus(200);

        $user = User::where('email', $user->email)->first();

        $this->assertTrue(Hash::check($password, $user->password));
    }
}
