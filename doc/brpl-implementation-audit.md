# BRPL 구현 점검 보고서

기준: 사용자 제공 BRPL 알고리즘(\(W_{xy}=\theta(Q_x-Q_y)-(1-\theta)ETX_{xy}\), 부모 선택은 `argmax W`)

## 결론 요약

현재 코드는 **"BRPL의 뼈대는 존재하지만, 문서 기준으로는 완전 구현이 아님"** 입니다.

- BRPL OF(객체 함수)와 BRPL 상태 변수(`theta`, `beta`, 평균 큐 등)는 존재함.
- 하지만 핵심 수식의 부호/가중 방식이 문서와 다르고, 큐/DIO 연동 경로가 끊긴 부분이 있어 실질적 백프레셔 동작이 약함.

## 항목별 점검

### 1) 기본 상태(`Q_x`, `Rank_x`, `ETX_xy`, `ParentSet`, `theta_x`)

- `theta`, `beta`, 평균 큐(`brpl_q_avg`)는 DAG 상태에 존재함.
- 부모별 큐 메타(`brpl_queue`, `brpl_queue_max`, `brpl_queue_valid`)도 parent 구조체에 존재함.
- 단, DIO 파서의 논리 구조체(`rpl_dio`)에는 BRPL 큐 필드가 없음.

판정: **부분 충족**

### 2) RPL cost (`Rank_parent + ETX`) 기반

- BRPL 구현에서 부모 경로 비용은 MRHOF의 `parent_path_cost()`를 그대로 사용하며, 기본적으로 `p->rank + link_metric` 형태임.

판정: **충족**

### 3) Backpressure (`Q_x - Q_y`)

- BRPL 가중치 계산에서 `delta_q = qx - qy`는 계산됨.
- 다만 큐 값은 별도 `brpl_queue_*` 계층인데, enqueue/dequeue/drop 훅이 실제 송신 큐 경로에서 호출되지 않음.

판정: **수식 일부만 존재(실측 큐 연동 미흡)**

### 4) 핵심 BRPL weight 수식 일치성

문서 기준:

- `W = theta * (Qx-Qy) - (1-theta) * ETX`
- 부모 선택: `argmax W`

현재 구현:

- `weight = theta * p_norm - (1-theta) * dq_norm`
- 그리고 `best_parent()`는 더 **작은** weight를 선택.

즉 내부적으로는 "비용 최소화" 관점이라 해석할 수 있으나,
문서가 요구한 `theta`의 의미(혼잡 시 backpressure 비중 증가) 및 `argmax W` 형태와는 **직접 일치하지 않음**.

판정: **불일치**

### 5) Parent 선택 알고리즘

- 후보 부모 비교 시 BRPL weight를 계산해 선택하는 로직은 존재함.
- 하지만 비교 방향이 `argmax`가 아니라 `min(weight)` 형태.

판정: **부분 충족(방향/해석 불일치)**

### 6) 패킷 스케줄링(`if W_xy > 0 send else hold`)

- 해당 형태의 per-packet hold/scheduling 게이트 로직은 확인되지 않음.
- 현재는 OF 기반 부모 선택 중심이며, "양의 weight일 때만 전송" 규칙이 코드에 없음.

판정: **미충족**

### 7) QuickTheta 자동 조정

- `rho`(큐 점유율 추정), `beta`(이웃 집합 변화율), `theta` 업데이트 로직은 존재함.
- 다만 문서 예시의 단순 `theta = Q_x / Q_max`와는 다르고,
  현재 식은 beta/rho 조합 기반으로 동작함.

판정: **개념 충족(수식은 상이)**

### 8) DIO 기반 큐 정보 전파

- parent 갱신 시 DIO의 `brpl_queue_*`를 읽는 코드는 있으나,
  DIO 파싱/생성 경로에서 해당 BRPL 옵션 처리 구현은 확인되지 않음.
- 또한 `BRPL_CONF_QUEUE_OPTION_CODE`는 정의되어 있지만 실제 사용처가 확인되지 않음.

판정: **미완성/연동 단절 가능성 큼**

## 최종 판정

문서의 알고리즘 요구사항 대비:

- **완전 일치 구현 아님**
- **부분 구현(OF 스켈레톤 + 일부 상태 업데이트) 단계**
- 특히 다음 3개가 핵심 갭:
  1. 문서식과 동일한 weight/선택 방향(`argmax`) 불일치
  2. 큐 계측 훅의 실 경로 미연동
  3. DIO 큐 옵션 전파 파이프라인 미완성

