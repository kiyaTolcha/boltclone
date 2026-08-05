export async function analyzeWithGemini(apiKey, findings, trafficMeta = {}) {
  if (!apiKey || typeof apiKey !== 'string') {
    throw new Error('Gemini API key is required for AI security analysis.');
  }

  const cleanApiKey = apiKey.trim();

  const prompt = `You are Antigravity, a Senior Principal Security Engineer & Penetration Tester.
Perform an executive threat assessment on the following API scan findings and network traffic metadata:

Target Application: ${trafficMeta.target || 'Web Application / API'}
Endpoints Scanned: ${trafficMeta.endpointCount || 1}
Findings Summary: ${JSON.stringify(findings, null, 2)}

Provide your response in JSON format with the following keys:
- "executiveSummary": A 2-3 sentence overview for C-level executives detailing overall security posture and risk.
- "attackPath": Description of potential attack chains or exploitation scenarios based on the findings.
- "priorityFixes": An array of actionable code/configuration fix recommendations.
- "overallRiskScore": An integer risk score between 0 (Lowest) and 100 (Critical).

Return ONLY valid raw JSON without markdown formatting or code blocks.`;

  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${encodeURIComponent(cleanApiKey)}`;

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: 0.2,
        maxOutputTokens: 1024
      }
    })
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Gemini API call failed (${res.status}): ${errorText}`);
  }

  const data = await res.json();
  const textResponse = data.candidates?.[0]?.content?.parts?.[0]?.text || '';

  try {
    const cleanedText = textResponse.replace(/^```json\s*/i, '').replace(/```\s*$/, '').trim();
    return JSON.parse(cleanedText);
  } catch {
    return {
      executiveSummary: textResponse.slice(0, 300) || 'AI analysis completed.',
      attackPath: 'Manual review recommended.',
      priorityFixes: ['Review findings against security guidelines.'],
      overallRiskScore: 50
    };
  }
}
