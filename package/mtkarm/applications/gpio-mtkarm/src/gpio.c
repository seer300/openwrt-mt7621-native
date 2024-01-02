/*
 ***************************************************************************
 * MEDIATEK Tech Inc.
 * 4F, No. 2 Technology 5th Rd.
 * Science-based Industrial Park
 * Hsin-chu, Taiwan, R.O.C.
 *
 * (c) Copyright, MEDIATEK Technology, Inc.
 *
 * All rights reserved. MEDIATEK's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of MEDIATEK Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of MEDIATEK Technology, Inc. is obtained.
 ***************************************************************************
 *
 * $Id: //WIFI_SOC/TRUNK/RT288x_SDK/source/user/rt2880_app/gpio/gpio.c#23 $
 */

#include <stdio.h>             
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <linux/autoconf.h>
#include "mediatek_gpio.h"

#define GPIO_DEV	"/dev/gpio"

void signal_handler(int signum)
{
	printf("gpio tester: signal ");
	if (signum == SIGUSR1)
		printf("SIGUSR1");
	else if (signum == SIGUSR2)
		printf("SIGUSR2");
	else
		printf("%d", signum);
	printf(" received\n", signum);
}
int gpio_test_intr(int gpio_num){
	int fd, req;
	mediatek_gpio_reg_info info;
	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return -1;
	}
	req = MEDIATEK_GPIO_REG_IRQ;
	info.irq = gpio_num;
	
	if (ioctl(fd, req, &info) < 0) {
		perror("ioctl error : MEDIATEK_GPIO_REG_IRQ ");
		close(fd);
	}
	close(fd);



	//issue a handler to handle SIGUSR1
	signal(SIGUSR1, signal_handler);
	signal(SIGUSR2, signal_handler);

	//wait for signal
	pause();
	return 0;

}

void gpio_set_led(int argc, char *argv[]){
	int fd;
	mediatek_gpio_led_info led;

	led.gpio = atoi(argv[2]);
	if (led.gpio < 0 || led.gpio >= MEDIATEK_GPIO_NUMBER) {
		printf("gpio number %d out of range (should be 0 ~ %d)\n", led.gpio, MEDIATEK_GPIO_NUMBER);
		return;
	}
	led.on = (unsigned int)atoi(argv[3]);
	if (led.on > MEDIATEK_GPIO_LED_INFINITY) {
		printf("on interval %d out of range (should be 0 ~ %d)\n", led.on, MEDIATEK_GPIO_LED_INFINITY);
		return;
	}
	led.off = (unsigned int)atoi(argv[4]);
	if (led.off > MEDIATEK_GPIO_LED_INFINITY) {
		printf("off interval %d out of range (should be 0 ~ %d)\n", led.off, MEDIATEK_GPIO_LED_INFINITY);
		return;
	}
	led.blinks = (unsigned int)atoi(argv[5]);
	if (led.blinks > MEDIATEK_GPIO_LED_INFINITY) {
		printf("number of blinking cycles %d out of range (should be 0 ~ %d)\n", led.blinks, MEDIATEK_GPIO_LED_INFINITY);
		return;
	}
	led.rests = (unsigned int)atoi(argv[6]);
	if (led.rests > MEDIATEK_GPIO_LED_INFINITY) {
		printf("number of resting cycles %d out of range (should be 0 ~ %d)\n", led.rests, MEDIATEK_GPIO_LED_INFINITY);
		return;
	}
	led.times = (unsigned int)atoi(argv[7]);
	if (led.times > MEDIATEK_GPIO_LED_INFINITY) {
		printf("times of blinking %d out of range (should be 0 ~ %d)\n", led.times, MEDIATEK_GPIO_LED_INFINITY);
		return;
	}

	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return;
	}
	if (ioctl(fd, MEDIATEK_GPIO_LED_SET, &led) < 0) {
		perror("ioctl");
		close(fd);
		return;
	}
	close(fd);
}
int gpio_output(int pin, int val){
	int fd, req;
	mediatek_gpio_reg_info info;
	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return -1;
	}
	req = MEDIATEK_GPIO_WRITE;
	info.pinnum = pin;
	info.value = val;
	if (ioctl(fd, req, &info) < 0) {
		perror("ioctl error : MEDIATEK_GPIO_WRITE ");
		close(fd);
	}
	close(fd);
	return 0;
}
int gpio_set_direction(int pin, int dir){
	int fd, req;
	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return -1;
	}
	
	if (dir == 0){
		req = MEDIATEK_GPIO_DIR_IN;// direction in
	}else if (dir == 1){
		req = MEDIATEK_GPIO_DIR_OUT;
	}
	

	if (ioctl(fd, req, pin) < 0) {
		perror("ioctl: set direction fail");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int gpio_read(int pin){
	int fd, req;
	mediatek_gpio_reg_info info;
	//printf("gpio_read pin=%d\n", pin);
	fd = open(GPIO_DEV, O_RDONLY);
	if (fd < 0) {
		perror(GPIO_DEV);
		return -1;
	}
  req = MEDIATEK_GPIO_READ;
  	info.pinnum = pin;
	if (ioctl(fd, req, &info) < 0) {
		perror("ioctl : MEDIATEK_GPIO_READ");
		close(fd);
		return -1;
	}
	
	printf("gpio number%d = %x\n", pin, info.value_in);

	close(fd);
}

void usage(char *cmd)
{
	printf("Usage: %s o <gpio> <value>- gpio output \n", cmd);
	printf("       %s d <gpio> <in/out>- gpio direction, in=0, out=1\n", cmd);
	printf("       %s r <gpio> - gpio input read\n", cmd);
	printf("       %s i (<gpio>) - interrupt test for gpio number\n", cmd);
	printf("       %s l <gpio> <on> <off> <blinks> <rests> <times>\n", cmd);
	printf("            - set led on <gpio>(0~24) on/off interval, no. of blinking/resting cycles, times of blinking\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		usage(argv[0]);

	switch (argv[1][0]) {

	case 'd':
		if (argc == 4)
			gpio_set_direction(atoi(argv[2]), atoi(argv[3]));
		else
			usage(argv[0]);
		break;
	case 'o':
		if (argc == 4)
			gpio_output(atoi(argv[2]), atoi(argv[3]));
		else
			usage(argv[0]);
		break	;	
	case 'r':
		if (argc == 3)
			gpio_read(atoi(argv[2]));
		else
			usage(argv[0]);
		break;
	case 'i':
		if (argc == 3)
			gpio_test_intr(atoi(argv[2]));
		else
			gpio_test_intr(0);
		break;
	case 'l':
		if (argc != 8)
			usage(argv[0]);
		gpio_set_led(argc, argv);
		break;
	default:
		usage(argv[0]);
	}
	
	return 0;
}