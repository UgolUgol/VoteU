import pickle

class Candidate :

    def __init__(self):
        self.name = ""
        self.second_name = ""
        self.patronymic = ""


class Blank:

    def __init__(self):
        self.candidates = []
        self.voices = []

    def add_candidate(self, name, second_name, patronymic):
        candidate = Candidate()
        candidate.name = name
        candidate.second_name = second_name
        candidate.patronymic = patronymic

        self.candidates.append(candidate)
        self.voices.append(0)

    def vote_for(self, idx, voice):
        self.voices[idx] = voice


    def copy(self):
        b = Blank()
        for i in range(len(self.candidates)):
            b.add_candidate(self.candidates[i].name, self.candidates[i].second_name,
                                self.candidates[i].patronymic)
        return b


    def print_candidate(self, idx):
        return (self.candidates[idx].name, self.candidates[idx].second_name)

    def print_candidate_voices(self, idx):
        return (self.voices[idx])

    def print_all(self):
        for i in range(len(self.candidates)):
            print(i + 1, " ", self.print_candidate(i))

    def print_full_blank(self):
        for i in range(len(self.candidates)):
            print(i + 1, " ", self.print_candidate(i), " ", self.print_candidate_voices(i))

    def __add__(self, other):
        for i in range(len(self.voices)):
            self.voices[i] += other.voices[i]
        return self