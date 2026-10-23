<template>
  <div
    v-if="html"
    class="w-full"
    v-html="html"
  />
</template>

<script>
// Přehled dokončeného QES podpisu v poli dokumentu (SPEC § 13): místo
// interního tokenu `qes:<id>` se zobrazí stejný HTML přehled jako v kartě
// podepisujícího. Server ho vrací v `summary_html` z `GET /s/:slug/qes_sessions/:id`.
export default {
  name: 'QesSummary',
  inject: ['baseUrl'],
  props: {
    value: { type: String, required: true },
    submitterSlug: { type: String, required: true }
  },
  data () {
    return {
      html: ''
    }
  },
  watch: {
    value: {
      immediate: true,
      handler () {
        this.load()
      }
    }
  },
  methods: {
    async load () {
      const id = /^qes:(\d+)$/.exec(this.value || '')?.[1]

      if (!id) {
        this.html = ''

        return
      }

      try {
        const response = await fetch(`${this.baseUrl}/s/${this.submitterSlug}/qes_sessions/${id}`, {
          headers: { Accept: 'application/json' }
        })
        const payload = await response.json()

        this.html = response.ok ? (payload.summary_html || '') : ''
      } catch {
        this.html = ''
      }
    }
  }
}
</script>
