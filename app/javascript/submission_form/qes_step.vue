<template>
  <div class="relative flex flex-col w-full items-center">
    <div
      v-if="field.title || field.name || showFieldNames"
      class="text-sm mb-2 w-full text-center"
      :class="field.description ? 'mb-4' : 'mb-2'"
    >
      <div class="font-medium text-base">
        {{ field.title || field.name || t('qes_step_title') }}
      </div>
      <div v-if="field.description" class="text-xs text-gray-500">
        {{ field.description }}
      </div>
    </div>

    <div class="w-full flex flex-col items-center gap-3" aria-live="polite">
      <template v-if="phase === 'idle'">
        <p class="text-sm text-gray-600 text-center">{{ t('qes_step_description') }}</p>
        <button
          type="button"
          class="btn btn-primary"
          :disabled="dryRun || !!nativePlatform"
          :title="dryRun ? t('qes_step_preview_disabled') : undefined"
          @click="createSession"
        >
          {{ t('qes_step_button') }}
        </button>
        <p v-if="!!nativePlatform" class="text-xs text-gray-500">{{ t('qes_step_native') }}</p>
      </template>

      <template v-else-if="phase === 'creating'">
        <span class="loading loading-spinner" />
      </template>

      <template v-else-if="phase === 'awaiting_app'">
        <p class="text-sm text-gray-600 text-center">{{ t('qes_step_waiting') }}</p>
        <div
          class="qes-qr bg-white p-2 rounded border"
          :aria-label="t('qes_step_button')"
          v-html="session.qr_svg"
        />
        <button type="button" class="btn btn-primary" @click="openApp">
          {{ t('qes_step_open_app') }}
        </button>
        <a :href="session.fallback_url" class="text-xs text-gray-500 underline" target="_blank">
          {{ t('qes_step_no_app') }}
        </a>
        <p class="text-xs text-gray-500">
          {{ expiresInText }}
        </p>
        <button type="button" class="btn btn-outline btn-sm" @click="cancelSession">
          {{ t('qes_step_cancel') }}
        </button>
      </template>

      <template v-else-if="phase === 'completed'">
        <p class="text-green-700 font-medium">
          {{ doneText }}
        </p>
      </template>

      <template v-else-if="phase === 'expired'">
        <p class="text-sm text-red-700">{{ t('qes_error_expired_token') }}</p>
        <button type="button" class="btn btn-primary btn-sm" @click="reset">
          {{ t('qes_step_new_link') }}
        </button>
      </template>

      <template v-else>
        <p class="text-sm text-red-700">{{ errorMessage }}</p>
        <button type="button" class="btn btn-primary btn-sm" @click="reset">
          {{ t('qes_step_retry') }}
        </button>
      </template>
    </div>
  </div>
</template>

<script>
import {
  cancelPath as qesStepCancelPath,
  cancelledState as qesStepCancelledState,
  createPollGuard as qesStepCreatePollGuard,
  doneText as qesStepDoneText,
  errorKey as qesStepErrorKey,
  expiresInText as qesStepExpiresInText,
  minutesLeft as qesStepMinutesLeft,
  nextBackoff as qesStepNextBackoff,
  pollTimedOut as qesStepPollTimedOut,
  terminalPhase as qesStepTerminalPhase
} from './qes_step_logic.mjs'

export default {
  name: 'QesStep',
  inject: ['baseUrl', 't'],
  props: {
    field: { type: Object, required: true },
    modelValue: { type: String, required: false, default: null },
    submitter: { type: Object, required: true },
    submitterSlug: { type: String, required: false, default: '' },
    showFieldNames: { type: Boolean, required: false, default: true },
    dryRun: { type: Boolean, required: false, default: false },
    nativePlatform: { type: String, required: false, default: '' }
  },
  emits: ['update:modelValue', 'attached', 'start', 'submit'],
  data() {
    return {
      phase: 'idle',
      session: null,
      error: null,
      level: this.field.preferences?.level || 'ades',
      pollTimer: null,
      pollGuard: qesStepCreatePollGuard(),
      backoff: 2000,
      startedAt: null
    }
  },
  computed: {
    minutesLeft() {
      return qesStepMinutesLeft(this.session?.expires_at)
    },
    errorMessage() {
      return this.error ? this.t(qesStepErrorKey(this.error)) : ''
    },
    // Korenový `t` v `form.vue` neumí interpolaci `{level}`/`{minutes}`;
    // texty z i18n.js proto skládáme tady.
    doneText() {
      return qesStepDoneText(this.t, this.level)
    },
    expiresInText() {
      return qesStepExpiresInText(this.t, this.minutesLeft)
    }
  },
  beforeUnmount() {
    this.stopPolling()
  },
  methods: {
    csrfToken() {
      return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
    },
    async post(path, body) {
      const response = await fetch(`${this.baseUrl}/s/${this.submitterSlug}${path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'X-CSRF-Token': this.csrfToken()
        },
        body: JSON.stringify(body)
      })
      const payload = await response.json().catch(() => ({}))
      if (!response.ok) {
        const error = new Error(payload.error || 'network')
        error.status = response.status
        error.code = payload.error || 'network'
        throw error
      }
      return payload
    },
    async createSession() {
      this.stopPolling()
      this.session = null
      const ticket = this.pollGuard.begin(null)
      this.phase = 'creating'
      this.$emit('start')
      try {
        const session = await this.post('/qes_sessions', { field_uuid: this.field.uuid })
        if (!ticket.isCurrent(this.session?.id ?? null)) return

        this.session = session
        this.phase = 'awaiting_app'
        this.startedAt = Date.now()
        this.schedulePoll(2000)
      } catch (error) {
        if (!ticket.isCurrent(this.session?.id ?? null)) return

        this.error = error.code || 'network'
        this.phase = 'failed'
      }
    },
    // Otevře appku z QR kódu / tlačítka (custom scheme).
    openApp() {
      if (!this.session) return

      window.location.href = this.session.custom_scheme_link
    },
    schedulePoll(delay) {
      this.pollTimer = setTimeout(this.poll, delay)
    },
    stopPolling() {
      this.pollGuard.invalidate()
      if (this.pollTimer) clearTimeout(this.pollTimer)
      this.pollTimer = null
    },
    async poll() {
      if (!this.session) return
      const ticket = this.pollGuard.begin(this.session.id)
      try {
        const state = await this.fetchState(ticket)
        if (!ticket.isCurrent(this.session?.id)) return
        this.backoff = 2000
        const terminal = qesStepTerminalPhase(state.state)
        if (terminal === 'completed') {
          this.stopPolling()
          this.level = state.level || this.level
          this.$emit('update:modelValue', state.value)
          this.$emit('submit')
          this.phase = 'completed'
          return
        }
        if (terminal) {
          this.stopPolling()
          this.error = state.error?.code || state.state
          this.phase = terminal
          return
        }
      } catch (error) {
        if (!ticket.isCurrent(this.session?.id)) return

        if (error.status === 410) {
          this.stopPolling()
          this.error = error.code
          this.phase = 'expired'
          return
        }
        this.backoff = qesStepNextBackoff(this.backoff)
      }
      if (!ticket.isCurrent(this.session?.id)) return

      if (qesStepPollTimedOut(this.startedAt)) {
        this.stopPolling()
        this.phase = 'expired'
        return
      }
      this.schedulePoll(this.backoff)
    },
    async fetchState(ticket) {
      const response = await fetch(
        `${this.baseUrl}/s/${this.submitterSlug}/qes_sessions/${ticket.sessionId}`,
        { headers: { Accept: 'application/json' }, signal: ticket.signal }
      )
      if (!ticket.isCurrent(this.session?.id)) return null

      const payload = await response.json().catch(() => ({}))
      if (!ticket.isCurrent(this.session?.id)) return null
      if (!response.ok) {
        const error = new Error(payload.error || 'network')
        error.status = response.status
        error.code = payload.error || 'network'
        throw error
      }
      return payload
    },
    async cancelSession() {
      const sessionId = this.session?.id
      this.stopPolling()
      Object.assign(this, qesStepCancelledState())
      if (!sessionId) return

      try {
        await this.post(qesStepCancelPath(sessionId), {})
      } catch {
        // zrušení je best-effort; session stejně vyprší
      }
    },
    reset() {
      this.stopPolling()
      this.phase = 'idle'
      this.session = null
      this.error = null
      this.backoff = 2000
    }
  }
}
</script>

