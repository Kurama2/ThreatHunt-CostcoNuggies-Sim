import numpy as np

def calculate_rubric_score(scores):
    """
    Self-evaluation rubric for ThreatHunt-CostcoNuggies-Sim.
    Input: Dict of criteria scores (1-5).
    Output: Final score (0-100%), verdict, breakdown.
    """
    # Fixed criteria and weights (sum 100%)
    criteria = {
        'Autonomy': 'Independent hunts like H1 geo split',
        'Teamwork': 'Alerts feeding SOAR for shared response',
        'Polyvalence': 'Tools like KQL, Python, Wazuh',
        'Curiosity': 'Hypotheses like "bypass + geo = threat?"',
        'Accuracy (Rule Precision)': '0.98 V3 tuning, <5 FPs',
        'Creativity': 'CostcoNuggies theme, Python mock pivots',
        'Impact': '84% FP drop, MTTR <1 min',
        'Adaptability': 'Pivots like n8n to Python mock'
    }
    weights = {
        'Autonomy': 20,
        'Teamwork': 15,
        'Polyvalence': 10,
        'Curiosity': 20,
        'Accuracy (Rule Precision)': 10,
        'Creativity': 5,
        'Impact': 10,
        'Adaptability': 10
    }

    # Validate scores match criteria
    missing = set(criteria.keys()) - set(scores.keys())
    if missing:
        raise ValueError(f"Missing scores for: {missing}")

    # Compute weighted score (normalize 1-5 to 0-100%, weight, sum)
    weighted_scores = []
    breakdown = []
    for key in criteria:
        sc = scores[key]  # Your 1-5 score
        wt = weights[key]
        ws = (sc / 5) * wt  # Normalize to 0-100%, then weight
        weighted_scores.append(ws)
        breakdown.append(f"{key}: {sc}/5 (Weight {wt}%) = {ws:.1f}%")

    final_score = np.sum(weighted_scores)

    # Verdict (thresholds for self-reflection)
    if final_score >= 90:
        verdict = "Exemplary – Hire-worthy execution!"
    elif final_score >= 75:
        verdict = "Strong – Solid foundation, minor polish."
    else:
        verdict = "Good Start – Focus on low-scorers for growth."

    return {
        'final_score': round(final_score, 1),
        'verdict': verdict,
        'breakdown': breakdown,
        'total_criteria': len(criteria)
    }

# Your self-scores with reasoning (edit 1-5 as needed)
if __name__ == "__main__":
    scores = {
        'Autonomy': 5,  # I decided to create this project on my own and did research to automate/simply tasks. I give myself a full score here.
        'Teamwork': 3,  # The project to begin with wasn't too teamwork oriented but I did ask for help regardless!
        'Polyvalence': 3,  # I'll stay humble and give a 3/5 since, while I used many tools, I master none of them yet.
        'Curiosity': 5,  # I dug deep to find answers and understand how to put together the project!
        'Accuracy (Rule Precision)': 4,  # Without testing it in real-life scenarios I can't give a full score.
        'Creativity': 5,  # I give myself credit here, I think the project is pretty cool and I'm proud for bringing my ideas to life this way
        'Impact': 4,  # In a real scenario, the impact would be massively important, but again since this is just a sim let's keep it humble.
        'Adaptability': 5  # Learning new tools, pivoting and adapting ideas to get the job done!
    }

    result = calculate_rubric_score(scores)
    print(f"Final Score: {result['final_score']}%")
    print(f"Verdict: {result['verdict']}")
    print("\nBreakdown:")
    for item in result['breakdown']:
        print(f"  • {item}")