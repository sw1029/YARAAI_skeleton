# YARAAI_skeleton

## Setup
Install dependencies and configure Git LFS:

```bash
pip install -r requirements.txt
git lfs install
export OPENAI_API_KEY=your-key  # or edit config.py
```


## pipeline

```
input: 
json file  



"get_metadata"
    path, module, base, size, md5, sha256, crc32, filesize
      
"get_current_address" - 16진수

"file_entropy" - 실수

"string_stats"
    string_count, avg_str_len, max_str_len

functions

  { name - str
    address - int
    size - 16진수
    instr_count - int
    branch_count - int
    cyclomatic - int
    xref_count - int
    disassembly - 여러개의 str
    }
```

1. json file의 get_metadata, get_current_address, file_entropy, string_stats는 str 형태로 기본 프롬포트에 내부 값과 함께 삽입한다.  


2. functions의 경우 내부 요소를 파싱하여 .asm 확장자로 변환한다.  


3. 별도의 api(따로 지정해 배포한 assembly 전용 요약 프로젝트)를 이용하여 .asm확장자로 변환한 assembly에 대한 자연어 설명을 얻은 뒤 기본 프롬포트에 삽입한다.


4. openAI api를 호출하기 전에 프롬포트 후반에
   "rule auto_generated { ... }" 형태의 YARA 룰을 반환하도록 명시하는
   문자열을 덧붙인다.
   이후 이 프롬포트를 사용해 yara rule 생성을 요청한다.


5. api 응답 str에서 yara rule을 파싱한다.


6. yara rule 검증용 라이브러리로 해당 결과를 검증한다.


7. 프로젝트의 result 폴더에 해당 yara rule을 저장한다.

8. 파싱 실패에 대비해 최대 세 번까지 OpenAI 호출을 재시도하고, 각 응답은
   `result/responses` 폴더에 저장한다.


# 추가 구현 사항
```
CLI 구현  
    1. 원본 실행파일(exe, dll)인지 json 파일인지에 따라 데이터 전처리를 다르게 하여 파이프라인에 데이터 삽입.
    2. 간단한 명령어를 통하여 파이프라인 제어
    3. 최종 결과물이 되는 yara rule의 오탐률 확인 - 이미 구현된 라이브러리를 import 하는 방식으로 검증도구 불러옴

Api call
    1. openAI 인증키는 별도의 설정파일에서 관리
    2. 별도의 api(따로 지정해 배포한 assembly 전용 요약 프로젝트)는 인터페이스 형태로 추상화하여 부름. 이 때 요약 호출은 api 호출을 wrapping 하는 class를 선언하여 가시성을 높임
    3. YARA rule 생성을 위해 기본적으로 `gpt-4.1` 모델을 사용
```

TODO - 코드에서 미구현된 부분
```
- `binary_to_json` 함수의 실제 실행 파일 분석 로직
- AssemblySummaryAPI를 외부 요약 서비스와 연동
- 오탐률 검증용 샘플 자동 수집 스크립트
- 입력 파일명을 활용한 동적 YARA 룰 이름 생성
```

### TODO
- `binary_to_json` 함수에 실행파일 파싱 로직 추가
- 오탐률 검증용 샘플 수집 자동화
- CLI에서 룰 이름을 지정할 수 있도록 개선
