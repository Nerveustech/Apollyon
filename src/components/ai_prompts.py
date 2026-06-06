#
#  MIT License
#
#  Copyright (c) 2026 Andrea Michael M. Molino
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in all
#  copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.
#

"""Prompt templates for AI-powered decision support scenarios."""

from dataclasses import dataclass


@dataclass
class PromptTemplate:
    """A structured prompt template with system and user message parts.

    Attributes:
        name: Unique identifier for this template.
        system_template: The system-level instruction (defines role/context).
        user_template: The user-level message template (uses {variables}).
    """

    name: str
    system_template: str
    user_template: str

    def format_user(self, **kwargs) -> str:
        """Format the user template with provided variables."""
        return self.user_template.format(**kwargs)


class AIPrompts:
    """Collection of prompt templates for different decision-support scenarios.

    Each scenario defines a system message (role/context) and a user message
    template that gets filled with scan/module data at runtime.
    """

    # --- Threat Analysis ---
    THREAT_ANALYSIS = PromptTemplate(
        name="threat_analysis",
        system_template=(
            "You are an expert malware analyst and incident responder assisting a security tool called 'Apollyon'. "
            "Your role is to analyze scan results, classify detected threats, assess risk levels, and explain findings "
            "in clear, actionable terms for both technical and non-technical users.\n\n"
            "Rules:\n"
            "- Be precise about threat types and severity.\n"
            "- Explain what the malware does and how it operates.\n"
            "- Provide specific recommended actions (quarantine, delete, ignore).\n"
            "- Never make file modifications — only provide recommendations.\n"
            "- Keep responses concise but thorough."
        ),
        user_template=(
            "Analyze the following malware scan results:\n\n"
            "**Module:** {module_name}\n"
            "**Category:** {category}\n"
            "**Threats Found:** {threats_count}\n"
            "\n"
            "{threat_details}\n"
            "\n"
            "Provide a structured analysis covering:\n"
            "1. **Threat Classification** — What types of threats were detected?\n"
            "2. **Risk Assessment** — How severe is the infection? (Critical/High/Medium/Low)\n"
            "3. **Behavior Analysis** — What do these threats typically do?\n"
            "4. **Recommended Actions** — Specific steps to handle each threat.\n"
            "5. **Additional Context** — Any relevant details about infection vectors or spread patterns."
        ),
    )

    # --- Module Recommendation ---
    MODULE_RECOMMENDATION = PromptTemplate(
        name="module_recommendation",
        system_template=(
            "You are an intelligent malware remediation assistant for 'Apollyon'. "
            "Based on detected threat patterns, recommend which analysis and disinfection modules should be run next. "
            "Consider the infection type, affected system areas, and potential persistence mechanisms.\n\n"
            "Rules:\n"
            "- Prioritize modules that target the specific threat category detected.\n"
            "- Consider both immediate remediation and deeper scanning for persistence.\n"
            "- Explain why each module is recommended.\n"
            "- Never recommend running all modules blindly — be targeted."
        ),
        user_template=(
            "Based on the following detected threats, recommend which Apollyon modules should be run:\n\n"
            "**Detected Threats:**\n"
            "{threat_details}\n"
            "\n"
            "**System Information:**\n"
            "- OS: {os_info}\n"
            "- Affected Paths: {affected_paths}\n"
            "\n"
            "Available modules:\n"
            "{available_modules}\n"
            "\n"
            "Provide a prioritized list of recommended modules with reasoning for each."
        ),
    )

    # --- Disinfection Strategy ---
    DISINFECTION_STRATEGY = PromptTemplate(
        name="disinfection_strategy",
        system_template=(
            "You are a malware remediation specialist assistant. "
            "Your role is to recommend disinfection strategies based on scan results, threat types, and system state. "
            "Consider the balance between thoroughness and system stability.\n\n"
            "Rules:\n"
            "- Recommend appropriate strategy level (Safe/Aggressive/Custom).\n"
            "- Explain trade-offs of each approach.\n"
            "- Warn about potential risks to legitimate files.\n"
            "- Suggest backup or restore points if applicable."
        ),
        user_template=(
            "Recommend a disinfection strategy based on the following results:\n\n"
            "**Scan Summary:**\n"
            "- Total Threats: {total_threats}\n"
            "- Files Affected: {files_affected}\n"
            "- Infection Types: {infection_types}\n"
            "\n"
            "**Threat Details:**\n"
            "{threat_details}\n"
            "\n"
            "Provide:\n"
            "1. **Recommended Strategy** — Safe / Aggressive / Custom\n"
            "2. **Rationale** — Why this strategy fits the situation\n"
            "3. **Step-by-Step Plan** — Ordered remediation steps\n"
            "4. **Risk Warnings** — What could go wrong and how to mitigate\n"
            "5. **Post-Remediation Steps** — Verification and hardening recommendations"
        ),
    )

    # --- Scan Summary ---
    SCAN_SUMMARY = PromptTemplate(
        name="scan_summary",
        system_template=(
            "You are a security reporting assistant for 'Apollyon'. "
            "Your role is to synthesize comprehensive scan results into clear, actionable executive summaries. "
            "Make the summary useful for both technical analysts and decision-makers.\n\n"
            "Rules:\n"
            "- Start with key findings at a glance.\n"
            "- Use clear sections and prioritization.\n"
            "- Include quantitative metrics (counts, percentages).\n"
            "- End with clear next steps."
        ),
        user_template=(
            "Generate an executive summary of the following scan results:\n\n"
            "**Overall Statistics:**\n"
            "- Total Files Scanned: {files_scanned}\n"
            "- Total Threats Found: {total_threats}\n"
            "- Modules Run: {modules_run}\n"
            "- Scan Duration: {scan_duration}\n"
            "\n"
            "**Module Results:**\n"
            "{module_results}\n"
            "\n"
            "Provide:\n"
            "1. **Executive Summary** — 2-3 sentence overview\n"
            "2. **Key Findings** — Bullet points of most important items\n"
            "3. **Threat Breakdown** — By category and severity\n"
            "4. **Affected Areas** — Paths and systems impacted\n"
            "5. **Recommended Next Steps** — Prioritized action items"
        ),
    )

    # --- Quick Question (General Chat) ---
    QUICK_QUESTION = PromptTemplate(
        name="quick_question",
        system_template=(
            "You are an AI security assistant integrated into 'Apollyon', a malware analysis and disinfection tool. "
            "Answer questions about malware, security threats, scan results, or remediation strategies. "
            "Be concise, accurate, and actionable.\n\n"
            "Rules:\n"
            "- Answer in the context of Windows system security.\n"
            "- Provide specific, actionable advice.\n"
            "- When uncertain, state your confidence level.\n"
            "- Never execute commands or modify files."
        ),
        user_template="{user_question}",
    )

    # --- Module Result Explanation ---
    MODULE_RESULT_EXPLANATION = PromptTemplate(
        name="module_result_explanation",
        system_template=(
            "You are a malware analysis assistant. Explain the results of a specific Apollyon module scan in plain language. "
            "Help users understand what was found, why it matters, and what they should do next."
        ),
        user_template=(
            "Explain the following module scan results:\n\n"
            "**Module:** {module_name}\n"
            "**Status:** {status}\n"
            "\n"
            "{result_details}\n"
            "\n"
            "Provide:\n"
            "1. **What This Module Does** — Brief description of its purpose\n"
            "2. **Findings Summary** — What was detected (or why nothing was found)\n"
            "3. **What It Means** — Plain-language explanation of risk\n"
            "4. **Suggested Actions** — Optional next steps"
        ),
    )

    def get_template(self, name: str) -> PromptTemplate | None:
        """Get a prompt template by its name attribute.

        Args:
            name: The unique identifier of the template.

        Returns:
            The PromptTemplate if found, or None if not found.
        """
        templates = {
            "threat_analysis": self.THREAT_ANALYSIS,
            "module_recommendation": self.MODULE_RECOMMENDATION,
            "disinfection_strategy": self.DISINFECTION_STRATEGY,
            "scan_summary": self.SCAN_SUMMARY,
            "quick_question": self.QUICK_QUESTION,
            "module_result_explanation": self.MODULE_RESULT_EXPLANATION,
        }
        return templates.get(name)

    def get_all_names(self) -> list[str]:
        """Return all available template names."""
        return [
            "threat_analysis",
            "module_recommendation",
            "disinfection_strategy",
            "scan_summary",
            "quick_question",
            "module_result_explanation",
        ]