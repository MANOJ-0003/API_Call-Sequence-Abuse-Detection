user_sequences = {}

def track_sequence(user, api_name):

    if user not in user_sequences:
        user_sequences[user] = []

    user_sequences[user].append(api_name)

    return user_sequences[user]


def reset_sequence(user):

    user_sequences[user] = []