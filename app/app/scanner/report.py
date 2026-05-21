WEIGHTS = {'critical': 20, 'high': 10, 'medium': 5, 'low': 2}

def calculate_score(results):
    score = 100
    for r in results:
        if r['status'] == 'fail':
            score -= WEIGHTS.get(r['severity'], 0)
    return max(0, min(100, score))
