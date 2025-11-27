<script lang="ts">
	import { getAccountStatus, isEmailVerified, isLoading } from '$lib/account_status.svelte';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { toast } from 'svelte-hot-french-toast';

	let dismissed = $state(false);
	let resending = $state(false);

	const status = $derived(getAccountStatus());
	const verified = $derived(isEmailVerified());
	const loading = $derived(isLoading());

	const showBanner = $derived(!loading && status && !verified && !dismissed);

	async function resendVerification() {
		if (resending) return;
		resending = true;

		try {
			const api = new KeycastApi();
			await api.post('/auth/resend-verification');
			toast.success('Verification email sent!');
		} catch (e: any) {
			toast.error(e.message || 'Failed to resend verification email');
		} finally {
			resending = false;
		}
	}
</script>

{#if showBanner}
	<div class="verification-banner">
		<div class="banner-content">
			<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" viewBox="0 0 256 256">
				<path d="M224,48H32a8,8,0,0,0-8,8V192a16,16,0,0,0,16,16H216a16,16,0,0,0,16-16V56A8,8,0,0,0,224,48ZM98.71,128,40,181.81V74.19Zm11.84,10.85,12,11.05a8,8,0,0,0,10.82,0l12-11.05,58,53.15H52.57ZM157.29,128,216,74.18V181.82Z"></path>
			</svg>
			<span>
				Please verify your email address ({status?.email}).
				<button class="resend-link" onclick={resendVerification} disabled={resending}>
					{resending ? 'Sending...' : 'Resend verification email'}
				</button>
			</span>
		</div>
		<button class="dismiss-btn" onclick={() => dismissed = true} aria-label="Dismiss">
			<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 256 256">
				<path d="M205.66,194.34a8,8,0,0,1-11.32,11.32L128,139.31,61.66,205.66a8,8,0,0,1-11.32-11.32L116.69,128,50.34,61.66A8,8,0,0,1,61.66,50.34L128,116.69l66.34-66.35a8,8,0,0,1,11.32,11.32L139.31,128Z"></path>
			</svg>
		</button>
	</div>
{/if}

<style>
	.verification-banner {
		background: rgba(251, 191, 36, 0.1);
		border: 1px solid rgba(251, 191, 36, 0.3);
		border-radius: 8px;
		padding: 0.75rem 1rem;
		margin: 0 1rem 1rem 1rem;
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
	}

	.banner-content {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		color: rgb(251 191 36);
		font-size: 0.9rem;
	}

	.banner-content svg {
		flex-shrink: 0;
	}

	.resend-link {
		background: none;
		border: none;
		color: rgb(251 191 36);
		text-decoration: underline;
		cursor: pointer;
		padding: 0;
		font-size: inherit;
	}

	.resend-link:hover {
		color: rgb(252 211 77);
	}

	.resend-link:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.dismiss-btn {
		background: none;
		border: none;
		color: rgb(251 191 36);
		cursor: pointer;
		padding: 0.25rem;
		opacity: 0.7;
		transition: opacity 0.2s;
	}

	.dismiss-btn:hover {
		opacity: 1;
	}
</style>
