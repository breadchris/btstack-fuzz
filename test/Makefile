
# Makefile to build and run all tests

SUBDIRS =  \
	avrcp \
	#att_db \
	#avdtp \
	#tlv_posix \
	#ble_client \
	#btstack_link_key_db \
	#des_iterator \
	#hfp \
	#linked_list \
	#sdp_client \
	#security_manager \
	# gatt_client \
	# maths \

subdirs:
	echo Building all tests
	@set -e; \
	for dir in $(SUBDIRS); do \
	  $(MAKE) -C $$dir; \
	done

clean:
	echo Clean all test
	@set -e; \
	for dir in $(SUBDIRS); do \
	  $(MAKE) -C $$dir clean; \
	done

test:
	echo Run all test
	@set -e; \
	for dir in $(SUBDIRS); do \
	  $(MAKE) -C $$dir test; \
	done


