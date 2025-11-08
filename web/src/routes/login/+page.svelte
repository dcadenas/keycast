<script lang="ts">
	import { goto } from '$app/navigation';
	import { toast } from 'svelte-hot-french-toast';
	import { KeycastApi } from '$lib/keycast_api.svelte';

	const api = new KeycastApi();

	let email = $state('');
	let password = $state('');
	let isLoading = $state(false);

	async function handleLogin() {
		if (!email || !password) {
			toast.error('Please enter both email and password');
			return;
		}

		try {
			isLoading = true;

			const response = await api.post<{ token: string; pubkey: string }>(
				'/auth/login',
				{ email, password },
				{ credentials: 'include' }
			);

			toast.success('Login successful!');

			// Cookie is set, redirect to settings
			goto('/settings/permissions');
		} catch (err: any) {
			console.error('Login error:', err);
			toast.error(err.message || 'Login failed. Please check your credentials.');
		} finally {
			isLoading = false;
		}
	}
</script>

<svelte:head>
	<title>Login - Keycast</title>
</svelte:head>

<div class="auth-page">
	<div class="auth-container">
		<h1>Sign In to Keycast</h1>
		<p class="subtitle">Access your remote signing sessions</p>

		<form onsubmit={(e) => { e.preventDefault(); handleLogin(); }}>
			<div class="form-group">
				<label for="email">Email</label>
				<input
					id="email"
					type="email"
					bind:value={email}
					placeholder="you@example.com"
					required
					disabled={isLoading}
				/>
			</div>

			<div class="form-group">
				<label for="password">Password</label>
				<input
					id="password"
					type="password"
					bind:value={password}
					placeholder="••••••••"
					required
					disabled={isLoading}
				/>
			</div>

			<button type="submit" class="btn-primary" disabled={isLoading}>
				{isLoading ? 'Signing in...' : 'Sign In'}
			</button>
		</form>

		<p class="auth-link">
			Don't have an account? <a href="/register">Create one</a>
		</p>

		<p class="auth-note">
			Team admins: Use <a href="/">NIP-07 browser extension</a> instead
		</p>
	</div>
</div>

<style>
	.auth-page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		background: #0a0a0a;
		padding: 2rem;
	}

	.auth-container {
		background: #1a1a1a;
		border: 1px solid #333;
		border-radius: 12px;
		padding: 3rem;
		max-width: 450px;
		width: 100%;
	}

	h1 {
		margin: 0 0 0.5rem 0;
		color: #bb86fc;
		font-size: 2rem;
	}

	.subtitle {
		color: #999;
		margin: 0 0 2rem 0;
	}

	.form-group {
		margin-bottom: 1.5rem;
	}

	label {
		display: block;
		margin-bottom: 0.5rem;
		color: #e0e0e0;
		font-size: 0.9rem;
		font-weight: 500;
	}

	input {
		width: 100%;
		padding: 0.75rem;
		background: #0a0a0a;
		border: 1px solid #444;
		border-radius: 6px;
		color: #e0e0e0;
		font-size: 1rem;
		box-sizing: border-box;
	}

	input:focus {
		outline: none;
		border-color: #bb86fc;
	}

	input:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.btn-primary {
		width: 100%;
		padding: 0.75rem;
		background: #bb86fc;
		color: #000;
		border: none;
		border-radius: 6px;
		font-size: 1rem;
		font-weight: 600;
		cursor: pointer;
		transition: background 0.2s;
	}

	.btn-primary:hover:not(:disabled) {
		background: #cb96fc;
	}

	.btn-primary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.auth-link {
		text-align: center;
		margin-top: 1.5rem;
		color: #999;
	}

	.auth-link a {
		color: #bb86fc;
		text-decoration: none;
	}

	.auth-link a:hover {
		text-decoration: underline;
	}

	.auth-note {
		text-align: center;
		margin-top: 2rem;
		padding-top: 1.5rem;
		border-top: 1px solid #333;
		color: #666;
		font-size: 0.85rem;
	}

	.auth-note a {
		color: #03dac6;
		text-decoration: none;
	}

	.auth-note a:hover {
		text-decoration: underline;
	}
</style>
