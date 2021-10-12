# List of REST messages

## EA - ITS service
#### GET http://localhost:8080/ea-its/

Returns the EA-ITS interface.

#### POST http://localhost:8080/ea-its/enroll/

Body: the EnrollmentRequest encoded in BASE64

A4IBAYKn7CMMwq6UM4CCrxR0V0qhKnZ3yJB7iRJog3cuLH3s2L6+KlAK16Vg1fREEl2olZhcEsl7m7mjE/4VDi+j3dtnz9EJMw9gxtGZD4DTlb1WhtX+63UhFP+CAUaMIOUwFvbmrAo5KqOqiEoA/gCP9Mhx/G8GxFetONZzddBu3IMRaZrw7dxA/V3hn94jaj7FAwzp5ms1YNjro1c+8Ja35NwNsu4UX+ySs1XR6EZsSywotf8nbnPKHdT1PSzr+nBDuRAsAK4iCu+oIpPq+pCfOzWail16KVy9NxvDIuvznFxvKQS56nGmsyH5FmYsZJTGXW0aFYKEQOfmaQ82/F7wS+zrLmrsYKCbTKHXKE5eaEPYYm2IupNpGrCG4FaL0Bd4P2gpBOyv5aAjCEg1tyrIoYmgm+gy6c0iuIq5bmXg89Y5rKQqHT1jCQBxSKX0UBL6AUIAGqTAn2HbZ8m4Lj+G/QR3hW2v69cB9sej76ZYuj4FNDlgSO79pOzdMU+Kl3Z0UFG/QhMHQGjfSs6axarfsg5fY6y58YGAQVUrnwmmJKbAsQ==


Sends the EnrollmentRequest to the EA.

#### GET http://localhost:8080/ea-its/enroll/

Get the EnrollmentCertificate if it was finished. Otherwise, get error.

## AA - ITS service
#### GET http://localhost:8080/aa-its/

Returns the AA-ITS interface.

#### POST http://localhost:8080/aa-its/authorize/

Body: the AuthorizationRequest encoded in BASE64

A4IBAYLJRAxUr236O4CDlrdG6PNo7Xf4QcaQGAjvDwWwXNP7Ft8AWrP6ObDb3KmIcUwm+y3kYoioHGM0gJzrL3vF1MWQ9OGnO1Ha/TVBK4Bx+3nvqFChtbhz0IOCAf+NF1jqRDIaThCiCiy6wLza3VJPM26T+8LSx467CCNpS4w3V5W2ds9iVucOJXCt1d6oiePqDyjDe2ahHn49ZnOrlnDq1DTpMNkhlkapV2WKaI2FDRHJhQS9qhm2yD6yfvOpR5htwkuiXIfMqUZZdppVywGwP/CVTkggdf7Z556+CgDabnikCI9B6ra/+BoCTM86JqqgRg5JNUjBecFiUproGr9MHCEDYW+7P7gFnb165O+n2FtlW6sBmPCFX2Zn12iO+zi9yCHOnWx1bwG2hnYWwGn9gZCgiASjx4BT+OLxFdCxgd4jL86O78kcUfe5Y1DKBBArZjldHUZthyT6W8G9tkEgISIDTGPNNKva2XWpb9MqTjO77c5GIgdTOfwgsAlmAZesZGt70G/NuZrMxBPdGeyq/kGD7WzA0unS2jUT7jIg5VgZlE8fT51e5pGg/6qK6rDavM9pVG7+kpmKVwgcyOqNh+1rRbnX2mO5dE4+pzofPcQkfnKzPXJZOffpzzIQUHlATJAI5EsiniRTplfyhKhyGvsKM0N1SqhD7gwE6EWNrb0eZ6G643u8LxeAyKzYJ+ntHk6UpCCxoD/o8A3eBWjz3mIHtYA1m2pOkL8ucDeXYFiP0k+CGhjF/o2LKkLr4XsuCykSY1bInHxGrgRStCguooDZ0ecpnrah84kr


#### GET http://localhost:8080/aa-its/authorize/

Get the AuthorizationCertificate if it was finished. Otherwise, get error.

## EA - AA sevice
This service is provided by EA and it validates the Authorization Requests.

#### GET http://localhost:8080/ea-aa/
Returns the EA-AA interface.

#### POST http://localhost:8080/ea-aa/validation
Body: the EnrollmentValidationRequest encoded in BASE64

A4IBAYKn7CMMwq6UM4CCqypja5udkvS4fbbHiQwX6uOPimOBm0SLBLvq9kpf9PSAlPMbr5B8lVFFmBrC137qVy2FzJfceD9BeE/rD9/0DoAi/mCMoR/WLbB2HyaCAaFoxGNHsF27bkDu4kuvgWgbeMIWVCIsWHL+kZNmyk9qhDcfYKFhUPVReXdvBPmBnJc/MTqzFDFnkUOcR/zLvnx6uOx857Ksuj1Xkg55jYObH6FSfCn4/8YjXkjEDhjBD12VFceXRnyVOY93IQM4s/lMROtaHiJWMxnzyShe+uuQnw6sO3LsrBrJzliAzbFaJhPUVevrg0V2hrPNDmRwWoAbcsP/QeWhPVoYW8vbQPzdzKqKdrgdEBfhVKDOWruwMakEbb/SMPd0oaO8dxSycEWUdP3lvnG8wVemx0pJWWLEPC0cLrsU3rvsY2hkt9BKQ8ZQnxSvU0X/f9o1ujCrUrHcTku+MxWbjaXT2japXrigyu2iG8TojqG3YsaGWSwF7OntQv3wu3SzAdQMB35csLt54Nb8JJcZqamJjpQabT8E6xoc4LqvyzhFfZVEacf4NFLGQ5EnVPz5ayeDaVoWcW9c2uIXPPsU31FH8d6F9mkkhGu0nA9eBruFw4rvxIE4Ve0sfGiEO3qWkeVedkQTCnS4kzWaM/i7WStUdaCDk7R1Y4I=

