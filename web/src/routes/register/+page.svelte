<script lang="ts">
	import { goto } from '$app/navigation';
	import { toast } from 'svelte-hot-french-toast';
	import { KeycastApi } from '$lib/keycast_api.svelte';

	const api = new KeycastApi();

	let email = $state('');
	let password = $state('');
	let confirmPassword = $state('');
	let isLoading = $state(false);

	async function handleRegister() {
		if (!email || !password) {
			toast.error('Please enter email and password');
			return;
		}

		if (password.length < 8) {
			toast.error('Password must be at least 8 characters');
			return;
		}

		if (password !== confirmPassword) {
			toast.error('Passwords do not match');
			return;
		}

		try {
			isLoading = true;

			const response = await api.post<{ token: string; pubkey: string; email: string }>(
				'/auth/register',
				{ email, password },
				{ credentials: 'include' }
			);

			toast.success(`Account created! Welcome ${email}`);

			// Cookie is set, redirect to settings
			goto('/settings/permissions');
		} catch (err: any) {
			console.error('Registration error:', err);
			toast.error(err.message || 'Registration failed. Please try again.');
		} finally {
			isLoading = false;
		}
	}
</script>

<svelte:head>
	<title>Register - Keycast</title>
</svelte:head>

<div class="auth-page">
	<div class="auth-container">
		<h1>Create Account</h1>
		<p class="subtitle">Get started with secure remote signing</p>

		<form onsubmit={(e) => { e.preventDefault(); handleRegister(); }}>
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
					placeholder="At least 8 characters"
					required
					minlength="8"
					disabled={isLoading}
				/>
			</div>

			<div class="form-group">
				<label for="confirm-password">Confirm Password</label>
				<input
					id="confirm-password"
					type="password"
					bind:value={confirmPassword}
					placeholder="Re-enter password"
					required
					minlength="8"
					disabled={isLoading}
				/>
			</div>

			<button type="submit" class="btn-primary" disabled={isLoading}>
				{isLoading ? 'Creating account...' : 'Create Account'}
			</button>
		</form>

		<p class="auth-link">
			Already have an account? <a href="/login">Sign in</a>
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
